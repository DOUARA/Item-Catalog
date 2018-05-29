#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import Flask, render_template
from flask import flash, request, redirect, url_for, jsonify
import time
import os

# Database Dependencies Import

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

# OAuth Dependencies Import

from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# SQLAlchemy Engine Binding

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

# Database session variable

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Running The Flask Application

app = Flask(__name__)


# override the default url_for(endpoint, **values) variable in template context

@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)


def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path, endpoint, filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


# 404 page

@app.errorhandler(404)
def page_not_found(e):
    return (render_template('404.html'), 404)


# Pass session_login variable to all templates

@app.context_processor
def inject_user():
    return dict(login_session=login_session)


# OAuth Methods And Routings
# Create anti-forgery state token

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase
                    + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Disconnect Method

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash('You have successfully been logged out.')
        return redirect(url_for('showCategories'))
    else:
        flash('You were not logged in!')
        return redirect(url_for('showCategories'))


# Facebook Sign In

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print('access token received %s ' % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r'
                             ).read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r'
                                 ).read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?' \
          'grant_type=fb_exchange_token&client_id=%s&' \
          'client_secret=%s&fb_exchange_token=%s' % \
          (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API

    userinfo_url = 'https://graph.facebook.com/v2.8/me'
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?' \
          'access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token must be stored in the login_session in order to properly logout

    login_session['access_token'] = token

    # Get user picture

    url = 'https://graph.facebook.com/v2.8/me/picture?' \
          'access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data['data']['url']

    # see if user exists

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h2 class="text-center">Welcome, '
    output += login_session['username']

    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += '" class="profile_pic_onLogin">'
    flash('You are now logged in as %s' % login_session['username'])
    print('done!')
    return output


# Facebook disconnect

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']

    # The access token must me included to successfully logout

    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
        % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return 'you have been logged out'


# Google Sign In
# Cient Id And Web Application Defining For gconnect method

CLIENT_ID = (
             json.loads(open('client_secrets.json', 'r').
                        read())['web']['client_id']
            )
APPLICATION_NAME = 'Item Ctalog Application'


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code

    code = request.data

    try:

        # Upgrade the authorization code into a credentials object

        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = (
                    make_response(json.dumps('Failed to upgrade the' +
                                             'authorization code.'
                                             ), 401)
                   )
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.

    access_token = credentials.access_token
    url = \
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' \
        % access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = (
                    make_response(json.dumps("Token's user ID doesn't" +
                                             "match given user ID."
                                             ), 401)
                   )
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.

    if result['issued_to'] != CLIENT_ID:
        response = \
            make_response(json.dumps("Token's client ID does not match app's."
                                     ), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = \
            make_response(json.dumps('Current user is already connected.'
                                     ), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # ADD PROVIDER TO LOGIN SESSION

    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one

    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " class="profile_pic_onLogin"> '
    flash('You are now logged in as %s' % login_session['username'])
    print('done!')
    return output


# Disconnect goole - Revoke a current user's token and reset their
# login_session

@app.route('/gdisconnect')
def gdisconnect():

    # Only disconnect a connected user.

    access_token = login_session.get('access_token')
    url = (
           'https://accounts.google.com/o/oauth2/revoke?token={}'.
           format(access_token)
          )
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        return 'You have been logged out.'
    else:
        del login_session['access_token']
        return 'You have been logged out.'


'''
 response =
 make_response(json.dumps('Failed to revoke token for given user.'), 400)
 response.headers['Content-Type'] = 'application/json'
 return response
'''
# JSON endpoint


@app.route('/catalog.json')
def catalogJson():
    categories = session.query(Category).all()
    categoriesList = []
    for category in categories:
        items = (
                 session.query(Item).
                 filter(Item.category_id == category.id).all()
                )
        categoriesList.append(category.serializeCategories(items))
    return jsonify(category=categoriesList)


# Home Page

@app.route('/')
def showCategories():
    items = session.query(Item).order_by(Item.id.desc()).limit(8).all()
    categories = (
                  session.query(Category.name, func.count(Item.category_id)).
                  join(Item).group_by(Item.category_id).
                  order_by(func.count(Item.category_id).desc()).all()
                 )
    return render_template('index.html', categories=categories,
                           items=items)


# Show All items in a category

@app.route('/catalog/<string:cat_title>/items')
def showItems(cat_title):
    categories = (
                  session.query(Category.name, func.count(Item.category_id)).
                  outerjoin(Item).
                  group_by(Item.category_id).
                  order_by(func.count(Item.category_id).desc()).all()
                 )
    category = session.query(Category).filter(Category.name == cat_title).one()
    category_id = category.id
    items = session.query(Item).filter(Item.category_id == category_id).all()
    if 'email' in login_session:
        user_id = getUserID(login_session['email'])
        return render_template('category.html', items=items,
                               category=category, user_id=user_id,
                               categories=categories)
    return render_template('category.html', items=items,
                           category=category, categories=categories)


# Show info about an item

@app.route('/catalog/<string:cat_title>/<string:item_title>')
def showItemInfo(cat_title, item_title):
    item = session.query(Item).filter(Item.name == item_title).one()
    if 'username' in login_session:
        user_id = getUserID(login_session['email'])
        if item.user_id == user_id:
            return render_template('item.html', item=item)
    return render_template('publicitem.html', item=item)


# Adding New Item

@app.route('/catalog/new', methods=['POST', 'GET'])
def addNewItem():

    # Restricted to only logged in users

    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    user_id = getUserID(login_session['email'])
    if request.method == 'POST':
        category = session.query(Category).filter(Category.name ==
                                                  request.form
                                                  ['category']).one()

        name = request.form['name']
        try:
            query = (
                     session.query(Item).
                     filter(Item.name == name,
                            Item.category_id == category.id).one()
                     )
            return render_template('itemexists.html')
        except Exception:
            newItem = Item(name=name,
                           description=request.form['description'],
                           category=category, user_id=user_id)
            session.add(newItem)
            session.commit()
            flash('The Item: %s, has been added successfully!'
                  % request.form['name'])
            return redirect(url_for('showItems', cat_title=category.name))
    else:
        categories = session.query(Category).all()
        return render_template('newitem.html', categories=categories)


# Edit An Item

@app.route('/catalog/<string:cat_title>/<string:item_title>/edit',
           methods=['POST', 'GET'])
def editItem(cat_title, item_title):

    # Restricted to only logged in users

    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    category = session.query(Category).filter(Category.name == cat_title).one()
    item = session.query(Item).filter(Item.name == item_title,
                                      Item.category_id == category.id).one()

    if item.user_id != getUserID(login_session['email']):
        return "You Don't Have The Right To Edit This Item"

    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category']:
            newCategory = session.query(Category).filter(Category.name ==
                                                         request.form
                                                         ['category']).one()
            item.category_id = newCategory.id
        session.add(item)
        session.commit()
        flash('The Item %s, has been edited succesfully!' % item.name)
        return redirect(url_for('showItemInfo',
                        cat_title=category.name, item_title=item.name))
    else:
        categories = session.query(Category).all()
        return render_template('edititem.html', item=item,
                               categories=categories)


# Delete An Item

@app.route('/catalog/<string:cat_title>/<string:item_title>/delete',
           methods=['POST', 'GET'])
def deleteItem(cat_title, item_title):

    # Restricted to only logged in users

    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    category = session.query(Category).filter(Category.name == cat_title).one()
    item = session.query(Item).filter(Item.name == item_title,
                                      Item.category_id == category.id).one()
    if item.user_id != getUserID(login_session['email']):
        return "You Don't Have The Right To Delete This Item"

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('The Item %s, has been deleted succesfully!' % item.name)
        return redirect(url_for('showItems', cat_title=category.name))
    else:
        return render_template('deleteitem.html', item=item)


# User's Methods
# get user id method

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


# Get user info method

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Create User Method

def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


if __name__ == '__main__':
    app.secret_key = 'Very_Secret_Key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
