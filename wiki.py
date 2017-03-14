#Irena HE
# -*- coding: utf-8 -*-
import webapp2
import os
import jinja2
import re
import hashlib
import hmac
import random
import string
import json
import cgi
#import logging
from google.appengine.ext import db
#from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

cookieSecret = "cookieSecret"
#for cookie
def make_secure_val(val):
    return hmac.new(cookieSecret, val).hexdigest()

class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    def render_json(self, d):
        self.response.headers['Content-Type'] = 'application/json; Charset-UTF-8'
        self.write(json.dumps(d))

    def set_secure_cookie(self, cookieName, val):
        cookieVal = '%s|%s' % (str(val), make_secure_val(str(val)))
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (cookieName, cookieVal))
    def read_secure_cookie(self, name):
        cookieVal = self.request.cookies.get(name)
        if cookieVal:
            val, valSecure = cookieVal.split('|')
            if valSecure == make_secure_val(val):
                return val
    def login(self, username, password, u = None):
        if not u:
            u = User.by_name(username)
            #same as: u = db.GqlQuery("SELECT * FROM User WHERE username = :username", username = username).fetch(limit=1)[0]
        if u and valid_pw(username, password, u.passwordHashed):
            self.set_secure_cookie("uid", u.key().id())
            return True
    def escape_html(self, s):
        #https://wiki.python.org/moin/EscapingHtml
        return cgi.escape(s)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('uid')
        self.user = uid and User.by_id(int(uid))
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

    def notfound(self):
        self.error(404)
        self.write('<h1>404: Not found</h1>')

#------------------user registration--------------------#
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def validUsername(username):
    return username and USER_RE.match(username)
def validPassword(password):
    return password and PASS_RE.match(password)
def validEmail(email):
    return not email or EMAIL_RE.match(email)


def make_salt():
    return ''.join(random.choice(string.letters) for x in range(5))
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s|%s' %(name, h, salt)
def valid_pw(name, pw, h):
    salt = h.split('|')[2]
    return h == make_pw_hash(name, pw, salt)

#parent
def users_key(group = 'default'):
    return db.Key.from_path('users', group)
class User(db.Model):
    username = db.StringProperty(required = True)
    passwordHashed = db.StringProperty(required = True)
    email = db.EmailProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, username):
        #https://cloud.google.com/appengine/docs/standard/python/datastore/queryclass
        return cls.all().filter('username =', username).get()

    @classmethod
    def register(cls, username, password, email = None):
        passwordHashed = str(make_pw_hash(username, password))
        return cls(parent = users_key(), username = username, passwordHashed = passwordHashed, email = email)


class Signup(WikiHandler):
    def get(self):
        nextUrl = self.request.headers.get('referer', '/')
        self.render('signup.html', nextUrl = nextUrl)
    def post(self):
        nextUrl = str(self.request.get('nextUrl'))
        if not nextUrl or nextUrl.startswith('/login'):
            nextUrl = '/'

        haveError = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username = username, email = email)

        usernameValid = validUsername(username)
        passwordValid = validPassword(password)
        emailValid = validEmail(email)

        if not usernameValid:
            params['errorUsername'] = "Invalid username"
            haveError = True
        else:
            queryResult = User.by_name(username)
            if queryResult:
                params['errorUsername'] = "Username already exists"
                haveError = True
        if not passwordValid:
            params['errorPassword'] = "Invalid password"
            haveError = True
        elif password != verify:
            params['errorVerify'] = "Your passwords didn't match"
            haveError = True
        if not emailValid:
            params['errorEmail'] = "Invalid email"
            haveError = True

        if haveError == False:
            if email:
                u = User.register(username, password, email)
            else:
                u = User.register(username, password)
            u.put()

            self.login(username, password, u)
            self.redirect(nextUrl)
        else:
            self.render('signup.html', **params)



#------------------user login logout--------------------#

class Login(WikiHandler):
    def get(self):
        nextUrl = self.request.headers.get('referer', '/')
        self.render('login.html', nextUrl = nextUrl)
    def post(self):
        nextUrl = str(self.request.get('nextUrl'))
        if not nextUrl or nextUrl.startswith('/login'):
            nextUrl = '/'

        username = self.request.get('username')
        password = self.request.get("password")

        if self.login(username, password):
            self.redirect(nextUrl)
        else:
            self.render('login.html', username = username, errorLogin = "Invalid login.")

class Logout(WikiHandler):
    def get(self):
        nextUrl = self.request.headers.get('referer', '/')
        self.response.headers.add_header('Set-Cookie', 'uid=; Path=/')
        self.redirect(nextUrl)


#------------------building a basic wiki--------------------#

class Page(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    lastModified = db.DateTimeProperty(auto_now = True)

    @staticmethod
    def wikipage_key(title):
        return db.Key.from_path('wikipage', title)

    @classmethod
    def by_title(cls, title):
        #https://cloud.google.com/appengine/docs/standard/python/datastore/queryclass
        return cls.all().ancestor(cls.wikipage_key(title)).order("-created")
    @classmethod
    def by_id(cls, v, title):
        return cls.get_by_id(v, parent = cls.wikipage_key(title))

    @classmethod
    def createEntry(cls, title, content):
        entry = cls(parent = cls.wikipage_key(title), title = title, content = content)
        entry.put()

    def as_dict(self):
        d = {'title': self.title,
            'content': self.content,
            'created': self.created.strftime('%c'),
            'lastModified': self.lastModified.strftime('%c')}
        return d

class MainPage(WikiHandler):
    def get(self):
        if self.user:
            self.render('front.html', username = self.user.username)
        else:
            self.render('front.html')

class EditPage(WikiHandler):
    def get(self, title):
        if self.user:
            v = self.request.get('v')
            if v:
                p = Page.by_id(int(v), title)
                if p:
                    self.render('editpage.html', title = p.title, content = p.content)
            else:
                self.render('editpage.html', title = title)
        else:
            self.redirect('/login')

    def post(self, title):
        if not self.user:
            self.redirect('/login')

        content = self.request.get('content')
        p = Page.by_title(title).get()
        if content:
            if p and content != p.content or not p:
                Page.createEntry(title, content)
            self.redirect('/%s' %title)
        else:
            self.render('editpage.html', title = title, content = content, error = 'content cannot be empty')

class WikiPage(WikiHandler):
    def get(self, title):
        v = self.request.get('v')
        if v:
            p = Page.by_id(int(v), title)
        else:
            p = Page.by_title(title).get()
        if p:
            if self.format == 'html':
                p.content = self.escape_html(p.content).replace('\n', '<br>')
                self.render('wikipage.html', p = p)
            else:
                self.render_json(p.as_dict())
        else:
            self.redirect('/_notfound?p='+ title)


class HistoryPage(WikiHandler):
    def get(self, title):
        historyP = Page.by_title(title)
        if self.format == 'html':
            self.render('history.html', title=title, historyP = historyP)
        else:
            return self.render_json([p.as_dict() for p in historyP])


class SearchRedirect(WikiHandler):
    def get(self):
        search = self.request.get('search')
        self.redirect('/%s' %search)

class NotFound(WikiHandler):
    def get(self):
        p = self.request.get('p')
        self.render('notfound.html', p = p)


#http://webapp2.readthedocs.io/en/latest/guide/routing.html
PAGE_RE = r'((?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/_edit/' + PAGE_RE, EditPage),
    ('/_history/' + PAGE_RE + '(?:\.json)?', HistoryPage),
    ('/search-redirect', SearchRedirect),
    ('/_notfound', NotFound),
    ('/' + PAGE_RE + '(?:\.json)?', WikiPage),
], debug=True)
