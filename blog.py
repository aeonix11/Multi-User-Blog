import os
import re
import random
import hashlib
import hmac
from string import letters
import time
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Some functions to make things easier
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def set_cookie(self, name, val):
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, val)
        )

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# User stuff.
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Different data models
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comments(db.Model):
    author = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    postID = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Likes(db.Model):
    postid = db.StringProperty(required=True)
    author = db.StringProperty(required=True)


# Handlers
class MainPage(BlogHandler):
    def get(self):
        self.write("Go to /blog for some real action")


class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')

        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        postID = post.key().id()
        # Creates comment query to get all the comments from a postID.
        comment = db.GqlQuery("SELECT * FROM Comments WHERE postID = '%s'"
                                % postID)
        for c in comment:
            print(c.author)

        al = Likes.all().filter('postid =', post_id)
        count = al.count()

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comment, likes=count)

    def post(self, post_id,):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        postID1 = post.key().id()
        postID = str(postID1)
        author = self.request.cookies.get('username')

        comment = self.request.get('comment')

        c = Comments(author=author, postID=postID, comment=comment)
        c.put()
        time.sleep(0.5)
        self.redirect('/blog/%s' % str(post.key().id()))


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.cookies.get('username')

        if subject and content:
            p = Post(parent=blog_key(),
                    subject=subject,
                    content=content,
                    author=author)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            username = self.request.get('username')
            x = str(username)
            self.set_cookie('username', x)
            self.login(u)
            self.redirect('/welcome')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        x = str(username)
        self.set_cookie('username', x)

        u = User.login(username, password)
        if u:
            self.login(u)

            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        # If user is not logged in username will not be
        # valid and he will be sent to signup.

        username = self.request.cookies.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/signup')


class Editpost(BlogHandler):
    def get(self, post_id):

        post = Post.get_by_id(int(post_id), parent=blog_key())
        # If user is logged in.
        if self.user:

            if post.author == self.user.name:

                self.render("editpost.html", post=post)

            else:
                self.response.out.write("You cannot edit other user's posts")

        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.request.get("update"):

            post = Post.get_by_id(int(post_id), parent=blog_key())

            if post.author == self.user.name:

                post.content = self.request.get('content')
                post.subject = self.request.get('subject')
                post.put()
                time.sleep(0.5)
                self.redirect('/blog/%s' % str(post_id))

            else:
                error = "You cannot edit other users' posts'"
                self.render(
                    "editpost.html",
                    post=post,
                    edit_error=error)

        elif self.request.get("cancel"):
            self.redirect('/blog/%s' % str(post_id))


class EditComment(BlogHandler):

    def get(self, post_id, comment_id):

        comment = Comments.get_by_id(int(comment_id))
    
        if comment:

            if comment.author == self.user.name:

                self.render("editcomment.html", comment=comment)

            else:
                error = "You cannot edit what isn't yours"
                self.render("editcomment.html", edit_error=error)

        else:
            error = "This comment does not exist, 404"
            self.render("editcomment.html", edit_error=error)

    def post(self, post_id, comment_id):

        if self.request.get("update_comment"):

            comment = Comments.get_by_id(int(comment_id))

            if comment.author == self.user.name:

                comment.comment = self.request.get('comment')
                comment.put()
                time.sleep(0.5)
                self.redirect('/blog/%s' % str(post_id))

            else:
                error = "You cannot edit what isn't yours!!!'"
                self.render(
                    "editcomment.html",
                    comment=comment.comment,
                    edit_error=error)

        elif self.request.get("cancel"):
            self.redirect('/blog/%s' % str(post_id))


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):

        comment = Comments.get_by_id(int(comment_id))
        # If comment exists.
        if comment:
            # If comment author is the logged in user
            if comment.author == self.user.name:
                #delete entity from database and sleep
                # so that the page can load after the database
                # has updated.
                db.delete(comment)
                time.sleep(0.7)
                self.redirect('/blog/%s' % str(post_id))

            else:
                self.write("You cannot delete other user's comments")

        else:
            self.write("This comment does not exist")


class Deletepost(BlogHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())

        if post:
            if post.author == self.user.name:
                db.delete(post)
                time.sleep(0.5)
                self.redirect('/blog/')
            else:
                self.write("You cannot delete other users posts," +
                            " how did you get here anyway?")
        else:
            self.write("You cannot delete what does not exists...404")


class Like(BlogHandler):
    def get(self, post_id):

        post = Post.get_by_id(int(post_id), parent=blog_key())
        postid = str(post_id)
        author = self.user.name
        Like1 = Likes(postid=postid, author=author)

        pl = Likes.all().filter('postid =', postid).filter('author =', author)
        count = pl.count()

        if not post.author == author:
            if count == 0:
                Like1.put()
                time.sleep(0.5)
                self.redirect('/blog/%s' % str(post_id))
            else:
                self.write("You cannot like a post more than once")
        else:
            self.write("You cannot like your own posts!!!")


class Unlike(BlogHandler):
    def get(self, post_id):

        post = Post.get_by_id(int(post_id), parent=blog_key())
        postid = str(post_id)
        author = self.user.name

        pl = Likes.all().filter('postid =', postid).filter('author =', author)
        count = pl.count()
        result = pl.get()

        if not post.author == author:
            if count >= 1:
                result.delete()
                time.sleep(0.5)
                self.redirect('/blog/%s' % str(post_id))
            else:
                self.write("you cannot unlike this post since" +
                        " you have no like on it")
        else:
            self.write("If you are only allowed to delete your own posts!!!")


app = webapp2.WSGIApplication({('/', MainPage),
                                ('/welcome', Welcome),
                                ('/blog/?', BlogFront),
                                ('/blog/([0-9]+)', PostPage),
                                ('/blog/newpost', NewPost),
                                ('/signup', Register),
                                ('/login', Login),
                                ('/logout', Logout),
                                ('/blog/([0-9]+)/editpost/', Editpost),
                                ('/blog/([0-9]+)/Deletepost', Deletepost),
                                ('/blog/([0-9]+)/editcomment/([0-9]+)',
                                    EditComment),
                                ('/blog/([0-9]+)/deletecomment/([0-9]+)',
                                    DeleteComment),
                                ('/blog/([0-9]+)/Like/', Like),
                                ('/blog/([0-9]+)/Unlike', Unlike)
                                 }, debug=True)
