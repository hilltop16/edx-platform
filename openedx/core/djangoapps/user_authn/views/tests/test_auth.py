import json
from django.test import TestCase
from django.conf import settings
from django.urls import reverse
from unittest import mock

class getPublicSigningJWKSFunctionTest(TestCase):
    def _get_jwks(self, accepts='application/json'):
        """ Get JWKS from the endpoint """
        url = reverse('get_public_signing_jwks')

        return self.client.get(url, HTTP_ACCEPT=accepts)

    @mock.patch.dict(settings.JWT_AUTH, {'JWT_PUBLIC_SIGNING_JWK_SET': None})
    def test_get_public_signing_jwks_with_no_jwk_set(self):
        """ Test JWT_PUBLIC_SIGNING_JWK_SET is undefined """
        resp = self._get_jwks()
        content = json.loads(resp.content)
        assert resp.status_code == 400
        assert 'JWK set is not found' in content['error']
    
    @mock.patch.dict(settings.JWT_AUTH, {'JWT_PUBLIC_SIGNING_JWK_SET': {'jwks': 'mocked-jwks'}})
    def test_get_public_signing_jwks_with_jwk_set(self):
        """ Test JWT_PUBLIC_SIGNING_JWK_SET is defined """
        resp = self._get_jwks()
        content = json.loads(resp.content)
        assert resp.status_code == 200
        assert 'mocked-jwks' in content['jwks']
