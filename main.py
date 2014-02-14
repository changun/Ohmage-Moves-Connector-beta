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
import os
from google.appengine.ext.webapp import template
import urllib
import json
import base64
from datetime import datetime
from google.appengine.api import urlfetch

MOVES_ACCESS_TOKEN_ENDPOINT = "https://api.moves-app.com/oauth/v1/access_token"

STREAM_VERSION = 20140213

OHMAGE_MOVES_CONNECTOR = "Ohmage-Moves-Connector"
OHMAGE_MOVES_STREAM = "org.ohmage.Moves"

ROOT_URL = "http://localhost:8080/"
CLIENT_ID = "0N2iXQ5Mu5a7js6tB66390ywpEC6P9A9"
CLIENT_SECRET = "zRGrj59CNFJm9aawWg38Yiz2Y33k1qXb5D6SDm7uUh2ZAwqPb8274uTCpbY7qH8O"

from Crypto.Cipher import AES
# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b16encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b16decode(e)).rstrip(PADDING)

# generate a random secret key
secret = os.urandom(BLOCK_SIZE)

# create a cipher object using the random secret
cipher = AES.new(secret)

class MainHandler(webapp2.RequestHandler):
    def get(self):
        path = os.path.join(os.path.dirname(__file__), 'templates/index.html')
        self.response.out.write(template.render(path, {'warning':''}))

    # the post function is supposed only called by AJAX
    def post(self):
        username = self.request.POST['username'];
        password = self.request.POST['password'];
        # login ohmage
        from google.appengine.api import urlfetch
        form_fields = {
          "user": username,
          "password": password,
          "client": OHMAGE_MOVES_STREAM
        }
        form_data = urllib.urlencode(form_fields)
        result = urlfetch.fetch(url="https://test.ohmage.org/app/user/auth_token",
            payload=form_data,
            method=urlfetch.POST,
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
        result = json.loads(result.content)

        if result["result"] == "success":
            # token from ohmage
            token = result["token"]
            # create redirected url
            redirected_url = urllib.quote_plus(ROOT_URL+"auth/?token="+EncodeAES(cipher,token))
            # check if user is using mobile
            uastring = self.request.headers.get('user_agent')
            moves_uri = None
            if "Mobile" in uastring:
                # this will start Moves app on Android
                moves_uri=("moves://app/authorize?client_id=" + CLIENT_ID
                                + "&redirect_uri=" + redirected_url
                                + "&scope=activity location")
            else:
                # this will redirect user to the Moves authentication page
                moves_uri=("https://api.moves-app.com/oauth/v1/authorize?response_type=code"
                              + "&client_id=" + CLIENT_ID
                              + "&redirect_uri=" + redirected_url
                              + "&scope=activity location")
            self.response.out.write({"result":"success", "redirect":moves_uri})
        else:
            self.response.out.write({"result":"success", "warning":"The given ohmage credentials are incorrect!"})

class OhmageAuthHandler(webapp2.RequestHandler):
    # the post function is supposed to be only called by AJAX
    def post(self):
        username = self.request.POST['username']
        password = self.request.POST['password']
        # login ohmage
        from google.appengine.api import urlfetch
        form_fields = {
          "user": username,
          "password": password,
          "client": OHMAGE_MOVES_STREAM
        }
        form_data = urllib.urlencode(form_fields)
        result = urlfetch.fetch(url="https://test.ohmage.org/app/user/auth_token",
            payload=form_data,
            method=urlfetch.POST,
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
        result = json.loads(result.content)

        if result["result"] == "success":
            # token from ohmage
            token = result["token"]
            # create redirected url
            redirected_url = urllib.quote_plus(ROOT_URL+"auth/?token="+EncodeAES(cipher,token))
            # check if user is using mobile
            uastring = self.request.headers.get('user_agent')
            moves_uri = None
            if "Mobile" in uastring:
                # this will start Moves app on Android
                moves_uri=("moves://app/authorize?client_id=" + CLIENT_ID
                                + "&redirect_uri=" + redirected_url
                                + "&scope=activity location")
            else:
                # this will redirect user to the Moves authentication page
                moves_uri=("https://api.moves-app.com/oauth/v1/authorize?response_type=code"
                              + "&client_id=" + CLIENT_ID
                              + "&redirect_uri=" + redirected_url
                              + "&scope=activity location")
            self.response.out.write(json.dumps({"result":"success", "redirect":moves_uri}))
        else:
            self.response.out.write(json.dumps({"result":"failure", "warning":"The entered ohmage credentials are incorrect!"}))

class MovesAuthHandler(webapp2.RequestHandler):
    def get(self):
        # recreate redirected url (must be identical as what we submitted to authorize endpoint)
        redirected_url = ROOT_URL+"auth/?token="+self.request.GET["token"]
        token = DecodeAES(cipher,self.request.GET["token"])
        # prepare POST form for access token
        form_fields = {
          'grant_type':'authorization_code',
          'code':self.request.GET['code'],
          "client_id": CLIENT_ID,
          'client_secret': CLIENT_SECRET,
          'redirect_uri': redirected_url
        }
        form_data = urllib.urlencode(form_fields)
        result = urlfetch.fetch(url=MOVES_ACCESS_TOKEN_ENDPOINT,
            payload=form_data,
            method=urlfetch.POST,
            headers={'Content-Type': 'application/x-www-form-urlencoded'})

        result = json.loads(result.content)
        # we have got the access token!
        if 'access_token' in result:
            access_token = result["access_token"]
            # get iso8601 timestamp with timezone
            iso8601 = datetime.utcnow().isoformat() + "+00:00"
            # prepare stream data
            data = [{"stream_id":"oauth",
                    "stream_version": STREAM_VERSION,
                    "metadata": {"id":iso8601,"timestamp":iso8601},
                    "data": result}]
            # prepare stream upload post
            form_fields = {
              'auth_token': token,
              'observer_id': OHMAGE_MOVES_STREAM,
              "observer_version": STREAM_VERSION,
              'data': json.dumps(data),
              'client': OHMAGE_MOVES_CONNECTOR
            }
            form_data = urllib.urlencode(form_fields)
            result = urlfetch.fetch(url="https://test.ohmage.org/app/stream/upload",
                                payload=form_data,
                                method=urlfetch.POST,
                                headers={'Content-Type': 'application/x-www-form-urlencoded'})
            result = json.loads(result.content)
            if result["result"]=="success" and len(result["invalid_points"]) == 0:
                # successfully upload to ohmage, now try out the acces token
                response = urlfetch.fetch(url="https://api.moves-app.com/api/1.1/user/profile?access_token=" + access_token,
                                method=urlfetch.GET,
                                headers={'Content-Type': 'application/x-www-form-urlencoded'})
                # get user's profile
                profile = json.loads(response.content)
                first_date = profile["profile"]["firstDate"]
                first_date = first_date[0:4] + "/"+ first_date[4:6] + "/"  + first_date[6:8]
                # render congratulation page
                path = os.path.join(os.path.dirname(__file__), 'templates/congratulations.html')
                self.response.out.write(template.render(path, {'data_since':first_date }))
                return

        # we only get here if something went wrong
        path = os.path.join(os.path.dirname(__file__), 'templates/index.html')
        self.response.out.write(template.render(path, {'warning':'Oops! Something went wrong. Give it another try?' }))



app = webapp2.WSGIApplication([
    ('/ohmage_auth/', OhmageAuthHandler),
    ('/auth/', MovesAuthHandler),
    ('/', MainHandler)
], debug=True)
