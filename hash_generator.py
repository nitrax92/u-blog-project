import hmac
import re
import random
import hashlib
import string
# Secret should be kept within a hidden file.
secret = "some secret"


# Regex of allowed username, password and emails in the system.
USER_RE = re.compile(r"[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def hash_str(s):
    return hmac.new(secret, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(username, pw, salt=None):
    if not salt:
        salt = make_salt()

    hashed_pw = hashlib.sha256(username+pw+salt).hexdigest()
    return "%s,%s" % (hashed_pw, salt)


def valid_pw(username, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(username, pw, salt)
