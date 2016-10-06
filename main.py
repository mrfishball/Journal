#!/usr/bin/env python

import os
import re
import random
import hashlib
import hmac
from datetime import datetime
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape = True)

secret = "uglymojohaha_hehe"

# Database

class User(db.Model):
	username = db.StringProperty(required=True)
	email = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent=users_key())

	@classmethod
	def by_name(cls, username):
		u = User.all().filter('username =', username).get()
		return u

	@classmethod
	def register(cls, username, pw, email):
		pw_hash = make_pw_hash(username, pw)
		return User(parent=users_key(), username=username, pw_hash=pw_hash, email=email)

	@classmethod
	def login(cls, username, pw):
		u = cls.by_name(username)
		if u and valid_pw(username, pw, u.pw_hash):
			return u

class Post(db.Model):
	author = db.ReferenceProperty(User, required=True, collection_name = 'posts')
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		pid = self.key().id()
		return render_str("post.html", p=self, pid=pid)

class Comment(db.Model):
	user = db.ReferenceProperty(User, required=True, collection_name = 'users_comment')
	post = db.ReferenceProperty(Post, required=True, collection_name = 'posts_comment')
	comment = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_id(cls, cid):
		return Comment.get_by_id(cid, parent=comments_key())

	def render(self):
		self._render_text = self.comment.replace('\n', '<br>')
		return render_str("comment-post.html", c=self)

class Like(db.Model):
	user = db.ReferenceProperty(User, required=True, collection_name = 'users')
	post = db.ReferenceProperty(Post, required=True, collection_name = 'posts')

# Secuirty section that performs hashing and crediential validation.

def make_secure_val(val):
	return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split("|")[0]
	if secure_val == make_secure_val(val):
		return val

#Create a string that consists of 5 random letters.
def make_salt(length=5):
	return "".join(random.choice(letters) for x in xrange(length))

def make_pw_hash(username, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(username + pw + salt).hexdigest()
	return "%s,%s" % (salt, h)

def valid_pw(username, pw, h):
	salt = h.split(",")[0]
	return h == make_pw_hash(username, pw, salt)

def users_key(group="default"):
	return db.Key.from_path("users", group)

def posts_key(name = "default"):
	return db.Key.from_path('posts', name)

def comments_key(name = "default"):
	return db.Key.from_path('comments', name)

# Helper functions

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def pretty_date(time=False):
    # Get a datetime object or a int() Epoch timestamp and return a
    # pretty string like 'an hour ago', 'Yesterday', '3 months ago',
    # 'just now', etc
	now = datetime.now()
	if type(time) is int:
	    diff = now - datetime.fromtimestamp(time)
	elif isinstance(time,datetime):
	    diff = now - time
	elif not time:
	    diff = now - now
	second_diff = diff.seconds
	day_diff = diff.days

	if day_diff < 0:
	    return ''

	if day_diff == 0:
	    if second_diff < 10:
	        return "Just now"
	    if second_diff < 60:
	        return str(second_diff) + " seconds ago"
	    if second_diff < 120:
	        return "A minute ago"
	    if second_diff < 3600:
	        return str(second_diff / 60) + " minutes ago"
	    if second_diff < 7200:
	        return "An hour ago"
	    if second_diff < 86400:
	        return str(second_diff / 3600) + " hours ago"
	if day_diff == 1:
	    return "Yesterday"
	if day_diff < 7:
	    return str(day_diff) + " days ago"
	if day_diff < 31:
	    return str(day_diff / 7) + " weeks ago"
	if day_diff < 365:
	    return str(day_diff / 30) + " months ago"
	return str(day_diff / 365) + " years ago"

# This regular expression checks if the length of username is between
# 8-20 characters and made up of numbers and letters only.
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{8,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

# Checks if the length of password is between 6-20 characters. 
PASS_RE = re.compile(r"^.{6,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

# Check if the email address entered is valid
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return email and EMAIL_RE.match(email)

# Global handler

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params["user"] = self.user
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, username, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header("Set-Cookie", "%s=%s; Path=/" % (username, cookie_val))

	def read_secure_cookie(self, username):
		cookie_val = self.request.cookies.get(username)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie("user_id", str(user.key().id()))

	def logout(self):
		self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")

	# Check and see if the user is already logged in before other functons
	# are ran. For example a user is trying to register a new account
	# but he/she is already logged in(already has an account).
	def loggedin(self):
		uid = self.read_secure_cookie("user_id")
		self.user = uid
		return self.user and User.by_id(int(uid))

	def liked(self, post_id):
		post = self.getCurrentPost(post_id)
		user = self.getCurrentUser()
		q = Like.all().filter('post =', post)
		q2 = q.filter('user =', user)
		if q2.get():
			return [q2.get(), "liked"]
		else:		
			return [q2.get(), "notliked"]

	def post_metric(self, post_id):
		post = self.getCurrentPost(post_id)
		comments = Comment.all().filter('post =', post)
		likes = Like.all().filter('post =', post)
		commentCount = 0
		likeCount = 0
		for comment in comments:
			commentCount += 1
		for like in likes:
			likeCount += 1
		return (likeCount, commentCount)

	def getComments(self, post_id):
		post = self.getCurrentPost(post_id)
		comments = db.GqlQuery("select * from Comment where post = :1 order by created desc", post)
		# comments = Comment.all().filter('post =', post)
		uid = self.read_secure_cookie("user_id")
		commentArray = []
		for comment in comments:
			if int(comment.user.key().id()) == int(uid):
				cTuple = (comment, pretty_date(comment.created), True)
			else:
				cTuple = (comment, pretty_date(comment.created), False)
			commentArray.append(cTuple)
		return commentArray

	def getCurrentPost(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=posts_key())
		post = db.get(key)
		return post

	def getCurrentUser(self):
		uid = self.read_secure_cookie("user_id")
		user = User.by_id(int(uid))
		return user

	def getLikes(self, post_id):
		post = self.getCurrentPost(post_id)
		q = Like.all().filter('post =', post)
		likes = 0
		for like in q:
			likes += 1
		return likes

	def initialize(self, *a,**kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		self.loggedin()

# Sign up/log in handler
# Check for inputs to see if user is trying to log in or sign up for a new account.
# Perform credential validations to see if they match the records in the database or
# if new credentials are eligible for setting up a new account.

class Processor(Handler):
	def get(self):
		self.render("index.html")

	def post(self):
		if self.request.get("login-submit"):
			self.username = self.request.get("username")
			self.password = self.request.get("password")
			self.signin()

		elif self.request.get("register-submit"):
			have_error = False
			self.username = self.request.get("username")
			self.password= self.request.get("password")
			self.verify = self.request.get("verify")
			self.email = self.request.get("email")

			# A dictionary to send all the parameters to rendering.
			params = dict(username=self.username, email=self.email)

			if not valid_username(self.username):
				params["error_username"] = "Invalid username."
				have_error = True

			if not valid_password(self.password):
				params["error_password"] = "Invalid password."
				have_error = True
			
			if self.password != self.verify:
				params["error_verify"] = "Passwords do not match."
				have_error = True

			if not valid_email(self.email):
				params["error_email"] = "Invalid email."
				have_error = True

			if have_error:
				self.render("index.html", **params)
			else:
				self.signup()

	def signin(self, *a, **kw):
		raise NotImplementedError

	def signup(self, *a, **kw):
		raise NotImplementedError

class RegisterLogin(Processor):
	def get(self):
		u = self.loggedin()
		if u:
			self.redirect('/welcome')
		else:
			self.render("index.html")

	def signin(self):
		u = User.login(self.username, self.password)
		if u:
			self.login(u)
			self.redirect("/welcome?username=" + self.username)
		else:
			msg = "Invalid password or username"
			self.render("index.html", error=msg)

	def signup(self):
		#make sure user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = "That user already exist."
			self.render("index.html", error=msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/welcome?username=' + self.username)

class Welcome(Handler):
	def get(self):
		u = self.loggedin()
		if u:
			self.render("welcome.html", username=u.username)
		else:
			self.redirect('/')

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/')

# A list of the 10 most recent posts

class Trending(Handler):
	def get(self):
		u = self.loggedin()
		if u:
			posts = db.GqlQuery("select * from Post order by created desc limit 10")
		    # Prettify each date string and then package it with the post object into a
		    # tuple.
			package = []
			for post in posts:
				comments = db.GqlQuery("select * from Comment where post = :1", post)
				metrics = self.post_metric(int(post.key().id()))
				# counter = 0;
				# for comment in comments:
				# 	counter += 1
				aTuple = (post, pretty_date(post.created), metrics)
				package.append(aTuple)
			self.render('trending.html', package=package)
		else:
			self.redirect('/')

# Post page

class PostPage(Handler):
	def get(self, post_id):
		u = self.loggedin()
		if u:
			post=self.getCurrentPost(post_id)
			post_time = pretty_date(post.created)
			like = self.getLikes(post_id)
			liked = self.liked(post_id)
			comments = self.getComments(post_id)
			if not post:
				self.error(404)
				return
			uid = self.read_secure_cookie("user_id")
			if int(uid) == int(post.author.key().id()):
				isAuthor = True
			else:
				isAuthor = False
			self.render("permlink.html", author=isAuthor, post=post, 
				post_time=post_time, like=like, liked=liked, comments=comments)
		else:
			self.redirect('/')

# New post page

class NewPost(Handler):
	def get(self):
		u = self.loggedin()
		if u: 
			self.render('newpost.html')
		else:
			self.redirect('/')

	def post(self):
		author = self.getCurrentUser();
		title = self.request.get("title")
		content = self.request.get("content")

		if title and content:
			a = Post(author=author, parent=posts_key(), title=title, content=content)
			a.put()
			self.redirect("/blog/%s" % str(a.key().id()))
		else:
			error = "Title and content are required fields"
			self.render('newpost.html', title=title, content=content, error=error)

# Edit posts

class EditPost(Handler):
	def get(self, post_id):
		uid = self.read_secure_cookie("user_id")
		post = self.getCurrentPost(post_id)
		u = self.loggedin();
		if u and int(uid) == int(post.author.key().id()):
			self.render("edit.html", post=post)
		else:
			self.render('abort.html')

	def post(self, post_id):
		title = self.request.get("title")
		content = self.request.get("content")
		if title and content:
			post=self.getCurrentPost(post_id)
			post.title = title
			post.content = content
			post.put()
			self.redirect("/blog/%s" % str(post_id))
		else:
			error = "Title and content are required fields"
			self.render('edit.html', title=title, content=content, error=error)

# Delete posts

class DeletePost(Handler):
	def get(self, post_id):
		uid = self.read_secure_cookie("user_id")
		post = self.getCurrentPost(post_id)
		u = self.loggedin();
		if u and int(uid) == int(post.author.key().id()):
			self.render('delete.html', post=post)
		else:
			self.render('abort.html')

	def post(self, post_id):
		post = self.getCurrentPost(post_id)
		post.delete()
		self.render('confirmde.html')

# Post comments 

class Commenting(Handler):
	def get(self):
		pass

	def post(self, post_id):
		user = self.getCurrentUser()
		post = self.getCurrentPost(post_id)
		comment = self.request.get("comment")

		if comment:
			c = Comment(user=user, parent=comments_key(), post=post, comment=comment)
			c.put()
			self.redirect("/blog/%s#posted-comment" % str(post_id))
		else:
			error = "Please leave a comment"
			self.redirect("/blog/%s#comment" % str(post_id))

# Edit comments

class CommentEdit(Handler):
	def get(self):
		pass

	def post(self, post_id):
		u = self.loggedin()
		content = self.request.get("comment")
		if u and content:
			cid = self.request.get("cid")
			currentComment = Comment.by_id(int(cid))
			currentComment.comment = content
			currentComment.put()
			self.redirect("/blog/%s#posted-comment" % str(post_id))

# Delete comments

class CommentDelete(Handler):
	def get(self):
		pass

	def post(self, post_id):
		cid = self.request.get("cid");
		comment = Comment.by_id(int(cid));
		if comment:
			comment.delete()
			self.redirect("/blog/%s#posted-comment" % str(post_id))
		else:
			self.redirect("/blog/%s#posted-comment" % str(post_id))

# Like or unlike posts (cannot like your own posts)

class LikePost(Handler):
	def get(self, post_id):
		self.redirect("/blog/%s" % str(post_id))

	def post(self, post_id):
		liked = self.liked(post_id)[0]
		if liked:
			liked.delete()
			self.redirect("/blog/%s#post-control" % str(post_id))
		else:
			post = self.getCurrentPost(post_id)
			user = self.getCurrentUser()
			like = Like(user=user, post=post)
			like.put()
			self.redirect("/blog/%s#post-control" % str(post_id))

app = webapp2.WSGIApplication([('/', RegisterLogin), 
	('/blog/newpost', NewPost), 
	('/welcome', Welcome), 
	('/logout', Logout), 
	('/blog/trending', Trending), 
	('/blog/([0-9]+)', PostPage), 
	('/blog/([0-9]+)/edit', EditPost), 
	('/blog/([0-9]+)/delete', DeletePost), 
	('/blog/([0-9]+)/like', LikePost), 
	('/blog/([0-9]+)/comment', Commenting), 
	('/blog/([0-9]+)/comment-edit', CommentEdit),
	('/blog/([0-9]+)/comment-delete', CommentDelete)], debug=True)