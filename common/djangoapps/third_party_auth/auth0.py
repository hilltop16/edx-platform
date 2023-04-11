"""
Auth0 implementation based on social-core library:
https://github.com/python-social-auth/social-core/blob/master/social_core/backends/auth0.py
"""
import json
import jwt
import requests
from urllib.parse import urlparse, urlencode

from social_core.backends.auth0 import Auth0OAuth2

class Auth0Backend(Auth0OAuth2):
    
    JWK_URL = 'https://2u-guid-staging.us.auth0.com/.well-known/jwks.json'
    DEFAULT_SCOPE = ["openid", "email", "profile"]
    
    def jwt_decode_token(self, token):
      header = jwt.get_unverified_header(token)
      domain = self.setting('DOMAIN')
      jwks = requests.get('https://{}/.well-known/jwks.json'.format(domain)).json()
      public_key = None
      for jwk in jwks['keys']:
          if jwk['kid'] == header['kid']:
              public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

      if public_key is None:
          raise Exception('Public key not found.')

      issuer = 'https://{}/'.format(domain)
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
    
    def auth_url(self):
      """Return redirect url"""
      param = {'audience': self.setting('AUDIENCE')}
      url = super().auth_url()
      url += ('&' if urlparse(url).query else '?') + urlencode(param)
      return url
