"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support github.com and github enterprise installations
OWM_HOST = os.environ.get('OWM_HOST') or 'localhost:3000'
OWM_API = '%s/api/user' % OWM_HOST

class OWMMixin(OAuth2Mixin):
    # _OAUTH_AUTHORIZE_URL = "http://%s/oauth/auth" % OWM_HOST
    _OAUTH_AUTHORIZE_URL = "http://%s" % OWM_HOST
    _OAUTH_ACCESS_TOKEN_URL = "http://%s/oauth/token" % OWM_HOST


class OWMLoginHandler(OAuthLoginHandler, OWMMixin):
    pass


class OWMOAuthenticator(OAuthenticator):
    
    login_service = "OWM"
       
    client_id_env = 'OWM_CLIENT_ID'
    client_secret_env = 'OWM_CLIENT_SECRET'
    login_handler = OWMLoginHandler
    
    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()
        
        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/
        
        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code
        )

        # url = "http://%s/oauth/token" % OWM_HOST
        url = "http://%s/oauth/token" % OWM_HOST

        req = HTTPRequest(url,
          method="POST",
          headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
          body="grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s" %(self.client_id, self.client_secret, code) # Body is required for a POST...
        )

        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
          "User-Agent": "JupyterHub",
          "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("http://%s" % OWM_API,
          method="GET",
          headers=headers
          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["login"]


class LocalOWMOAuthenticator(LocalAuthenticator,OWMOAuthenticator):

    """A version that mixes in local system user creation"""
    pass

