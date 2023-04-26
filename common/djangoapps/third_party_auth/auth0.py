"""
Auth0 implementation based on social-core library:
https://github.com/python-social-auth/social-core/blob/master/social_core/backends/auth0.py
Auth0 authorization flow is used here
https://auth0.com/docs/get-started/authentication-and-authorization-flow/which-oauth-2-0-flow-should-i-use#is-the-client-a-web-app-executing-on-the-server-
"""
import json
import jwt
import requests
from urllib.parse import urlparse, urlencode

from social_core.backends.auth0 import Auth0OAuth2

class Auth0Backend(Auth0OAuth2):
    # Scope is a required parameter for Auth0 /oauth2/authorize endpoint
    # There is no value in the DEFAULT_SCOPE in Auth0OAuth2 class, we need extend from it to add scopes
    # At least openid has to be in the scope otherwise won't be able to retrieve id_token/access_token
    # We probably don't need this custom Auth0 backend if there are other ways to customize DEFAULT_SCOPE 
    DEFAULT_SCOPE = ["openid", "email", "profile"]
    
    def jwt_decode_token(self, token):
      header = jwt.get_unverified_header(token)
      # Get settings from third_party_auth module settings
      domain = self.setting('DOMAIN')
      jwks = requests.get('https://{}/.well-known/jwks.json'.format(domain)).json()
      public_key = None
      for jwk in jwks['keys']:
          if jwk['kid'] == header['kid']:
              public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

      if public_key is None:
          raise Exception('Public key not found.')

      issuer = 'https://{}/'.format(domain)
      # The audience is same as the client's key because both the client and the authorizing party are the app itself
      return jwt.decode(token, public_key, audience=self.setting('KEY'), issuer=issuer, algorithms=['RS256'])


    def get_user_details(self, response):
        # Obtain JWT and the keys to validate the signature
        id_token = response.get("id_token") or response.get('access_token')
        payload = self.jwt_decode_token(id_token)
        fullname, first_name, last_name = self.get_user_names(payload["name"])
        return {
            "username": payload["nickname"],
            "email": payload["email"],
            "email_verified": payload.get("email_verified", False),
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
            "picture": payload["picture"],
            "user_id": payload["sub"],
        }

