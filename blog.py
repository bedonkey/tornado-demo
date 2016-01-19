#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import bcrypt
import concurrent.futures
import psycopg2
import markdown
import os.path
import tornado.ioloop
import re
import subprocess
import tornado.escape
from tornado import gen
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import unicodedata
from psycopg2.extras import RealDictConnection, RealDictCursor

from tornado.options import define, options

conn_string = "host='localhost' dbname='blog' user='Bedonkey' password=''"
# A thread pool to be used for password hashing with bcrypt.
executor = concurrent.futures.ThreadPoolExecutor(2)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/archive", ArchiveHandler),
            (r"/feed", FeedHandler),
            (r"/entry/([^/]+)", EntryHandler),
            (r"/compose", ComposeHandler),
            (r"/auth/create", AuthCreateHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            blog_title=u"Work3ing Blog",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            ui_modules={"Entry": EntryModule},
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            debug=True,
        )
        super(Application, self).__init__(handlers, **settings)
        
class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        user_id = self.get_secure_cookie("blogdemo_user")
        if not user_id: return None
        return self.getUserFromID(user_id)

    def getUserFromID(self, user_id):
        print "UserID:" + user_id
        cur = self.db.cursor(cursor_factory = RealDictCursor)
        cur.execute("SELECT * FROM authors WHERE id = %s" % int(user_id))
        user = cur.fetchone()
        cur.close();
        if not user: return
        print user
        return user


class HomeHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        cur = self.db.cursor(cursor_factory = RealDictCursor)
        cur.execute(
            "SELECT id, author_id, slug, title, markdown, html, published, updated "
            "FROM entries ORDER BY published "
            "DESC LIMIT 5")
        entries = cur.fetchall()
        cur.close()
        self.render("home.html", entries=entries)

class EntryHandler(BaseHandler):
    def get(self, slug):
        print slug
        cur = self.db.cursor(cursor_factory = RealDictCursor)
        cur.execute("SELECT * FROM entries WHERE slug = '%s'" % slug)
        entry = cur.fetchone()
        cur.close()
        print entry
        if not entry: raise tornado.web.HTTPError(404)
        self.render("entry.html", entry=entry)


class ArchiveHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        cur = self.db.cursor(cursor_factory = RealDictCursor)
        cur.execute("SELECT * FROM entries ORDER BY published DESC")
        entries = cur.fetchall()
        cur.close()
        self.render("archive.html", entries=entries)


class FeedHandler(BaseHandler):
    def get(self):
        cur = self.db.cursor(cursor_factory = RealDictCursor)
        cur.execute("SELECT * FROM entries ORDER BY published "
                                "DESC LIMIT 10")
        self.set_header("Content-Type", "application/atom+xml")
        entries = cur.fetchall()
        cur.close()
        self.render("feed.xml", entries=entries)


class ComposeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        id = self.get_argument("id", None)
        entry = None
        if id:
            cur = self.db.cursor(cursor_factory = RealDictCursor)
            cur.execute("SELECT * FROM entries WHERE id = %s" % int(id))
            entry = cur.fetchone();
            cur.close()
        self.render("compose.html", entry=entry)

    @tornado.web.authenticated
    def post(self):
        id = self.get_argument("id", None)
        title = self.get_argument("title")
        text = self.get_argument("markdown")
        html = markdown.markdown(text)
        if id:
            cur = self.db.cursor(cursor_factory = RealDictCursor)
            cur.execute("SELECT * FROM entries WHERE id = %s" % int(id))
            entry = cur.fetchone();
            if not entry: raise tornado.web.HTTPError(404)
            slug = entry['slug']
            cur.execute(
                "UPDATE entries SET title = '%s', markdown = '%s', html = '%s' "
                "WHERE id = %s" % (title, text, html, int(id)))
            self.db.commit()
            cur.close()
        else:
            slug = unicodedata.normalize("NFKD", title).encode(
                "ascii", "ignore")
            slug = re.sub(r"[^\w]+", " ", slug)
            slug = "-".join(slug.lower().strip().split())
            if not slug: slug = "entry"
            while True:
                print "In while loop"
                cur = self.db.cursor(cursor_factory = RealDictCursor)
                cur.execute("SELECT * FROM entries WHERE slug = '%s'" % slug)
                e = cur.fetchall();
                cur.close()
                if not e: break
                slug += "-2"

            print "========>====>" + slug
            print self.current_user
            cur = self.db.cursor(cursor_factory = RealDictCursor)
            cur.execute(
                "INSERT INTO entries (author_id,title,slug,markdown,html,"
                "published) VALUES ('%s','%s','%s','%s','%s',NOW())" %
                (self.current_user['id'], title, slug, text, html))
            self.db.commit()
            cur.close()
        self.redirect("/entry/" + slug)


class AuthCreateHandler(BaseHandler):
    def get(self):
        self.render("create_author.html")

    @gen.coroutine
    def post(self):
        hashed_password = yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            bcrypt.gensalt())
        cur = self.db.cursor(cursor_factory = RealDictCursor)
        cur.execute(
            "INSERT INTO authors (email, name, hashed_password) VALUES ('%s', '%s', '%s') RETURNING id" % 
            (self.get_argument("email"), self.get_argument("name"), hashed_password))
        self.db.commit()
        author_id = cur.fetchone()['id']
        cur.close()
        self.set_secure_cookie("blogdemo_user", str(author_id))
        self.redirect(self.get_argument("next", "/"))


class AuthLoginHandler(BaseHandler):
    def get(self):
        # If there are no authors, redirect to the account creation page.
        self.render("login.html", error=None)

    @gen.coroutine
    def post(self):
        cur = self.db.cursor(cursor_factory = RealDictCursor)
        cur.execute("SELECT * FROM authors WHERE email = '%s'" % self.get_argument("email"))
        author = cur.fetchone()
        cur.close()
        if not author:
            self.render("login.html", error="email not found")
            return
        print author
        print "Pass: " + self.get_argument("password")
        hashed_password = yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(author['hashed_password']))
        print hashed_password
        if hashed_password == author['hashed_password']:
            self.set_secure_cookie("blogdemo_user", str(author['id']))
            self.redirect(self.get_argument("next", "/"))
        else:
            self.render("login.html", error="incorrect password")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        print "Logout"
        self.clear_cookie("blogdemo_user")
        self.redirect(self.get_argument("next", "/"))


class EntryModule(tornado.web.UIModule):
    def render(self, entry):
        return self.render_string("modules/entry.html", entry=entry)


def main():
    tornado.options.parse_command_line()
    application = Application();
    application.db = psycopg2.connect(conn_string)
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(8888)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()
