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
import webapp2
import logging
from webapp2_handler import GeneralHandler
from hash_generator import *


from google.appengine.ext import db


# Datastore Tabels
class User(db.Model):
    username = db.StringProperty(verbose_name="User Name", required=True)
    password = db.StringProperty(verbose_name="Password", required=True)
    email = db.StringProperty()

    @classmethod
    # NB, get_by_id might need parent param.
    def by_id(cls, user_id):
        return User.get_by_id(user_id)

    @classmethod
    def by_username(cls, u_name):
        # Get all user objects, filter by given username and get to pick the 1 (first?)
        u = User.all().filter('username', u_name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        hashed_pw = make_pw_hash(name, pw)
        return User(username=name, password=hashed_pw, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_username(name)
        if u and valid_pw(name, pw, u.password):
            return u


# Blog Section
class Post(db.Model):
    title = db.StringProperty(verbose_name="Title", required=True)
    quote = db.StringProperty(verbose_name="Main blog quote", multiline=True)
    content = db.TextProperty(required=True)
    image = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)
    edited = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User, collection_name="blogs", required=True)
    votes = db.IntegerProperty(default=0)

    @classmethod
    def by_user(cls, user):
        # Get all blog objects to this user
        u = Post.all().filter('user', user).order('created')
        return u


    @classmethod
    # NB, get_by_id might need parent param.
    def by_id(cls, blog_id):
        return Post.get_by_id(blog_id)

    @classmethod
    def get_comments(cls, blog_post):
        comments = Comment.all().filter('blog_post', blog_post).order('-created')
        return comments


class Comment(db.Model):
    blog_post = db.ReferenceProperty(Post, collection_name="Post comments")
    comment = db.StringProperty(multiline=True)
    created = db.DateTimeProperty(auto_now_add=True)
    edited = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def by_post(cls, post):
        comments = Comment.all().filter('blog_post', post)
        return comments



class Handler(GeneralHandler):
    # User System functions.
    # Cookie Functions
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Gotten from Udacity Course Solution
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainHandler(Handler):
    def get(self):
        # Gather the 5 most recent posts, sorted by date most recent.
        posts = ''
        posts = db.GqlQuery("select * from Post ORDER BY created desc")[:5]
        logging.info(posts)
        self.render("index.html", posts=posts)


# USER SYSTEM
class SignUp(Handler):
    def get(self):
        if self.user:
            logging.info("Already Signed in?? %s" % self.user)
            self.redirect('/')
        self.render("user/signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.password_conf = self.request.get('password_conf')
        self.email = self.request.get('email')

        # Standard Info to be given no matter the outcome
        self.context = {
            'username': self.username,
            'email': self.email
        }

        if not valid_username(self.username):
            self.context['error_username'] = "Not valid username"
            have_error = True

        if not valid_password(self.password):
            self.context['error_password'] = "Not valid password"
            have_error = True
        elif self.password != self.password_conf:
            self.context['error_password_conf'] = "Passwords did not match"
            have_error = True

        if have_error:
            self.render('user/signup.html', message="Error",  **self.context)
        else:
            self.done()


class Register(SignUp):
    def done(self):
        user = User.by_username(self.username)

        if user:
            msg = "User Already Exists"
            self.context['error_username'] = msg
            self.render('signup.html', **self.context)

        else:
            user = User.register(self.username, self.password, self.email)
            user.put()

            self.login(user)
            self.redirect('/')


class Login(Handler):
    def get(self):
        self.render('user/login.html')

    def post(self):
        users = User.all()
        for user in users:
            logging.info(user.username)
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)

            given_redirect_path = self.request.get('next')

            if given_redirect_path:
                self.redirect(given_redirect_path)
            else:
                self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('user/login.html', message=msg, error=msg)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


class ViewPost(Handler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))

        if post:
            comments = Comment.by_post(post)
            if not comments:
                comments = None
            logging.info(comments)
            self.render("blog/blog_post.html", post=post, comments=comments)

        else:

            self.redirect("/")

    def post(self, post_id):
        # Posted comment to blog_post
        comment = self.request.get("comment_text")
        error_message = ''
        if post_id.isdigit():
            Blog_post = Post.get_by_id(int(post_id))

            if comment:
                new_comment = Comment(blog_post=Blog_post, comment=comment, user=self.user)
                new_comment.put()
                new_comment.save()
            else:
                error_message = "Did you remember a comment?"
            comments = Blog_post.get_comments(Blog_post)
            self.render("blog/blog_post.html", message=error_message, post=Blog_post, comments=comments)

        else:
            self.redirect("/")


class NewPost(Handler):
    def get(self):
        if not self.user:
            self.redirect("/login?next=/blog/new")

        self.render("blog/new_post.html")

    def post(self):
        title = self.request.get("post_title")
        content = self.request.get("post_content")
        image = self.request.get("post_image")
        quote = content[:150]
        user = self.user

        content = content.replace('\n', '<br>')
        if not user:
            self.redirect("/login?next=/blog/new")

        # All good.
        if title and content:
            b = Post(title=title, content=content, user=user, quote=quote, image=image)
            Post.put(b)
            b.save()
            self.redirect("/")

        else:
            self.render("blog/new_blog.html", message="Missing information.", title=title, content=content)
            # ERROR; ERROR; ERROR; ERROR; ERROR


class EditBlogEntry(Handler):
    def get(self, blog_id):
        entry = Post.get_by_id(int(blog_id))

        if entry and self.user and entry.user.key() == self.user.key():
            self.render("blog/new_post.html", post=entry)
        else:
            self.redirect("/")

    def post(self, blog_id):
        entry = Post.get_by_id(int(blog_id))

        if entry and self.user and entry.user.key() == self.user.key():
            entry.title=self.request.get('post_title')
            entry.content=self.request.get('post_content')
            entry.put()
        self.redirect("/")


# View for displaying all post of one concretre user.
class UserPosts(Handler):
    def get(self, username):
        user = User.by_username(username)
        if user:
            blog_entries = Post.by_user(user)
            for blog in blog_entries:
                logging.info(blog.key())
        self.redirect("/")


class Vote(Handler):
    def get(self, post_id):
        blog_post = Post.get_by_id(int(post_id))
        if blog_post:
            if not self.user or blog_post.user.key().id() != self.user.key().id():
                blog_post = self.vote(blog_post)
                blog_post.put()

        self.redirect("/view/%s" % post_id)


class UpVote(Vote):
    def vote(self, blog_post):
        blog_post.votes += 1
        return blog_post


class DownVote(Vote):
    def vote(self, blog_post):
        blog_post.votes -= 1
        return blog_post


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/register', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/new', NewPost),
    ('/user/([a-zA-Z0-9_-]\w+)', UserPosts),
    ('/view/([0-9]+)', ViewPost),
    ('/edit/([0-9]+)', EditBlogEntry),
    ('/upvote/([0-9]+)', UpVote),
    ('/downvote/([0-9]+)', DownVote)
], debug=True)
