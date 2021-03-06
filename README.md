# Description

A simple python Flask application that provides a list of items within a variety of categories as well as provide a user registration and authentication system using OAuth 2.0 providers: google and facebook. 
Registered users have the ability to post, edit and delete their own items.
the application provides a JSON endpoint to that list all the categories and items


# Requirements And Dependencies

- Python 2.7 
- [SQLAlchemy ORM](http://docs.sqlalchemy.org/en/latest/intro.html)
- [Flask Framework.](http://flask.pocoo.org/docs/1.0/installation/)
- SQLite3
- You Need to have a [facebook](https://developers.facebook.com/docs/apps/register/) and [google](https://console.developers.google.com/flows/enableapi?apiid=fitness) developer apps in order to use the Authentication System

# Files and Structure
- Server side code: project.py
- Database: database_configuration.py
- Templates reside on template folder
- Images and css files reside on the static folder 

# Running the application 
Clone the repository to your machine: 
```
  https://github.com/DOUARA/Item-Catalog.git item-catalog
```
- Facebook Authentication: Add your facebook cliend_id and client_secret to the file named: fb_client_secrets.json, then authorise the redirect to the link below from your app dashboard:  
           http://localhost:5000

 - Google Authentication: authorise the redirect to the following links from within your app dashboard: 
           http://localhost:5000/login, 
           http://localhost:5000/gconnect
and add the link:    http://localhost:5000 to  the Authorized JavaScript origins.

Then download the json file that contains the app secret from within your app dashboard then copy its content to the file named: client_secrets.json. 
add your client id to login.html template (search for the placeholder {{YOUR-CLIENT-ID}} )

- Run the application using the command: 
```
 `python project.py` 
```
- Browse the application from the link: http://localhost:5000 
- JSON end point: http://localhost:5000/catalog.json 

# Live preview
https://item-catalog.douara.me/
