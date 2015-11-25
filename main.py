#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#IMPORTS
import webapp2
import os
import jinja2 #html templates
import re #used to make regular expressions
import hashlib #used to hash sensitive user data
import random #used to make random values
import string #addition string functions
import logging #pythyon standard logging module used for debugging
import json #used for creating the .json of blog and posts
import datetime #used to set dates and times

from google.appengine.ext import db #database to store blog posts
from google.appengine.api import memcache #memory cache used for caching 

#load html templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#Regular expressions to store the valid user entries
userRegExp = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
passRegExp = re.compile(r"^.{3,20}$")
emailRegExp = re.compile("^[\S]+@[\S]+\.[\S]+$")



#FUNCTIONS
#functions to validate if input is valid
def validUsername(username): 
    usernamesDB = db.GqlQuery("SELECT * FROM Logins")
    for user in usernamesDB:
        if user.username == username: #username is in database
            return "2"
    if userRegExp.match(username): #new username is not valid reg exp
        return "1"
    else:
        return None #username not in database
def validPassword(password):
    return passRegExp.match(password)
def validEmail(email):
    return emailRegExp.match(email)

#function to make a SALT for hashing
def makeSalt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

#function to hash users password
#this function should have a secret string constant used to in order to make secure
def hashStr(name, password, salt=None):
    if not salt:
        salt = makeSalt()
    hashedPass = hashlib.sha256(name + password + salt).hexdigest() #secret added here
    return hashedPass + "|" + salt

#function to verify correct username password
def validPw(name, password):
    #check if username exists
    usernames = db.GqlQuery("SELECT * FROM Logins")
    for user in usernames:
        if (user.username == name):
            #get salt for the username
            salt = user.password.split("|")[1]
            #check if raw creditials provided by user match the database creditentials
            return hashStr(name, password, salt) == user.password

#format database Entry to .json style 
def getJson(currentEntry):
    #create dictionary and store values
    entryJson = {} 
    entryJson["subject"] = currentEntry.subject
    entryJson["content"] = currentEntry.content
    entryJson["created"] = str(currentEntry.created.ctime())
    return entryJson


#CACHE
def blogFront(update = False):
    key = 'top'
    posts = memcache.get(key)
    if posts == None or update:
        logging.info("DB QUERY")
        posts = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC")
        posts = list(posts)
        memcache.set(key, posts)
        time = datetime.datetime.now()
        memcache.set("updated", time)
    return posts


#CLASSES            
#database for blog posts
class Entry(db.Model):
    subject = db.StringProperty(required = True)
    content = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

#database for user logins
class Logins(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True) #includes salt after hashed password
    email = db.StringProperty
    #salt = db.StringProperty(required = True)




#HANDLERS    
#jinja2 HTML template 
class Handler(webapp2.RequestHandler):
    #used to write html to site in shorthand maner
        #self.write instead of self.response.out.write
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    #load the template and pass it back    
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    #used to initiate the template
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#will be main page hub at later date
#/
class MainHandler(Handler):
    def get(self):
        self.render("main.html")

#handler for /blog main blog homepage- lists blog entries
#/blog
class BlogHandler(Handler):
    def get(self):
        #get the database entries cursers
        #entries = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC")

        #get posts from database or cache
        entries = blogFront()
        #write posts to page
        #logging.info(entries)

        updated = memcache.get("updated")
        #logging.info(updated)
        seconds = datetime.datetime.now() - updated
        #logging.info("seconds = " + str(seconds))
        seconds = str(seconds.total_seconds())
        #logging.info("seconds2 = " + seconds)
        self.render("blog.html", entries=entries, seconds=seconds)

        

#handler for /newpost used for creating new blog entry
#/newpost
class PostHandler(Handler):
    #render html with variables
    def render_post(self, subject="", content="", error=""):
        self.render("post.html", subject=subject, content=content, error=error) 
    
    def get(self):
        self.render_post()

    def post(self):
        #get user entered content
        subjectEntered = self.request.get("subject")
        content = self.request.get("content")
        #check to see if information was entered
        if subjectEntered and content:
            #create the database entry
            ent = Entry(subject = subjectEntered, content = content)
            #store in database
            ent.put()
            id = ent.key().id()
            #update cache
            blogFront(True)
            redirect = "/blog/" + str(id)
            self.redirect(redirect)
        #data wasn't entered. rerender page with data that was entered
        else:
            error = "Please enter both a subject and entry"
            self.render_post(subject = subjectEntered, content = content, error = error)

#handler for /signup - new user sign up for blog
#/signup
class SignHandler(Handler):
    #render html page
    def get(self, username="", password="", verify="", email="", error1="",
            error2="", error3="", error4=""):
        #render page with empty data
        self.render("sign.html", username=username, password=password, verify=verify, email=email,
                    error1=error1, error2=error2, error3=error3, error4=error4)

    def post(self):
        #check for valid input here, rerender form if invalid and give error message
        #if valid redirect to a welcome page
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        #if information is valid redirect to welcome page
        if (validUsername(username) == "1") and validPassword(password) and (validEmail(email) or email == "") and (password == verify):            
            #set cookie for username
            username = str(username)
            self.response.headers.add_header('Set-Cookie', 'userId=%s; Path=/' % username)
            
            #set cookie for password
            passwordHash = hashStr(username, password)
            passwordHash = str(passwordHash)
            self.response.headers.add_header('Set-Cookie', 'userPass=%s; Path=/' % passwordHash)
            
            #add username, e-mail, and password to the database
            email = str(email)
            login = Logins(username = username, password = passwordHash, email = email)
            login.put()
            id = login.key().id()

            #redirect to user welcome page
            self.redirect("/blog/welcome")

        #if errors, reprint entries and display error information
        else:
            error1 = ""
            error2 = ""
            error3 = ""
            error4 = ""
            
            if validUsername(username) == None:
                error1 = "invalid username"
            if validUsername(username) == "2":
                error1 = "username taken"
            if validPassword(password) == None:
                error2 = "invalid password"
            if validEmail(email) == None and email != "":
                error4 = "invalid email"
            if password != verify:
                error3 = "passwords do not match"
            #rerender page with user inforamtion and errors
            self.render("sign.html", username=username, password="", verify="", email=email,
                    error1=error1, error2=error2, error3=error3, error4=error4)

#handler for new user signup confirmation redirect
#/welcome
class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        #name = self.request.get("username")
        #get username from cookie
        nameCookie = self.request.cookies.get("userId")

        #get hashed password and salt from cookie
        passCookie = self.request.cookies.get("userPass")
        #salt = passCookie.split("|")[1]
        #passHash = passCookie.split("|")[0]
        databaseEntry = db.GqlQuery("SELECT * FROM Logins ")
        for entry in databaseEntry: #this loop is needed to initiate database
            logging.info(entry.username)
        #verify if login information matches information in database
        dbEntry = db.GqlQuery("SELECT * FROM Logins WHERE username = :name", name = nameCookie)
        logging.info(nameCookie)
        logging.info(dbEntry.get())
        #dbEntryPass = dbEntry.get().password
        if nameCookie == "":
            self.redirect('/blog/signup')
        elif passCookie == dbEntry.get().password:      
            self.response.write("Welcome, " + nameCookie + "!")
        else:
            self.redirect('/blog/signup')

#handler for the user login page
#/login
class LoginHandler(Handler):
    def render_post(self):
        self.render("login.html")
        
    def get(self):
        self.render_post()

    def post(self):
        username = self.request.get("username")
        password= self.request.get("password")
        ##self.write(username + password)
        if validPw(username, password):
            
            #set cookie for username
            usernameCook = str(username)
            self.response.headers.add_header('Set-Cookie', 'userId=%s; Path=/' % usernameCook)
            #set cookie for password
            dbEntry = db.GqlQuery("SELECT * FROM Logins WHERE username = :name", name = username)
            passwordHash = dbEntry.get().password
            passwordHash = str(passwordHash)
            self.response.headers.add_header('Set-Cookie', 'userPass=%s; Path=/' % passwordHash)
            
            self.redirect("/blog/welcome")
        else:
            self.render("login.html", loginError = "Invalid Data")

#handler for logout of a user
#/logout
class LogoutHandler(Handler):
    def get(self):
        #delete info from cookies
        self.response.headers.add_header('Set-Cookie', 'userId=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'userPass=; Path=/')
        #redirect to signup page
        self.redirect('/blog/signup')

#handler for json on main blog post
#/blog/.json
class BlogJsonHandler(Handler):
    def get(self):
        #set content type to json instead of text/html
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        #get blog entries
        blogEntries = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC")
        #store entries in a list
        jsonBlog = []
        for post in blogEntries:
            jsonPost = getJson(post) #get class with properties set up
            jsonBlog.append(jsonPost) #add class to list
        #output in json format    
        self.write(json.dumps(jsonBlog))

#handler for json on a post
#/blog/(postid).json
class EntryJsonHandler(Handler):
    def get(self, post_id):
        #set content type to json instead of text/html
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        #get post database entry
        entry = Entry.get_by_id(int(post_id))
        #output in json format
        self.write(json.dumps(getJson(entry)))

#handler for new post confirmation
#/blog/(postid)
class EntryHandler(Handler):
    def get(self, post_id):
        #get cache info
        entries = blogFront()
        found = False #value to deterime if in cache
        #check if post in already in cache
        for entry in entries:
            if str(entry.key().id()) == post_id:
                updated = memcache.get("updated")
                #determine when db was cached
                seconds = datetime.datetime.now() - updated
                seconds = str(seconds.total_seconds())
                self.render("entry.html", entry = entry, seconds = seconds)
                found = True
        #update cache since post was not found
        if found == False:
            blogFront(True)
            entry = Entry.get_by_id(int(post_id))
            seconds = datetime.datetime.now() - entry.created
            seconds = str(seconds.total_seconds()) 
            self.render("entry.html", entry = entry, seconds = seconds)

#handler to flush the cache
#/blog/flush
class FlushHandler(Handler):
    def get(self):
        #flush cache and redirect to main page
        memcache.flush_all()
        self.redirect("/blog")
        

    
#maps url to hadler to user
app = webapp2.WSGIApplication([
    ('/', MainHandler,), ('/blog/?', BlogHandler),
    ('/blog/newpost/?', PostHandler),
    (r'/blog/(\d*)/?', EntryHandler),
    ('/blog/signup/?', SignHandler),
    ('/blog/welcome/?', WelcomeHandler),
    ('/blog/login/?', LoginHandler),
    ('/blog/logout/?', LogoutHandler),
    ('/blog/.json/?', BlogJsonHandler),
    ('/blog/flush/?', FlushHandler),
    (r'/blog/(\d*).json/?', EntryJsonHandler)],debug=True)
