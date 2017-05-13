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

class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write('Helloo world!')

app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
