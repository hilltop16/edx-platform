from django.test import TestCase, Client
from django.conf import settings
from common.djangoapps.util.json_request import JsonResponse
from unittest.mock import patch

class getPublicSigningJWKSFunctionTest(TestCase):
    def setUp(self):
        self.client = Client()

    @patch('common.djangoapps.util.json_request.JsonResponse')
    def test_get_public_signing_jwks_with_no_jwk_set(self, mock_json_response):
        settings.JWT_AUTH = {}  
        response = self.client.get('/auth/jwks.json')  
        self.assertEqual(mock_json_response.call_args[0][0], {'error': 'JWK set is not found'})
        self.assertEqual(mock_json_response.call_args[1]['status'], 400)

    @patch('common.djangoapps.util.json_request.JsonResponse')
    def test_get_public_signing_jwks_with_jwk_set(self, mock_json_response):
        settings.JWT_AUTH = {'JWT_PUBLIC_SIGNING_JWK_SET': {'mocked-jwks': 'jwks'}}  
        response = self.client.get('/auth/jwks.json')
        self.assertEqual(mock_json_response.call_args[0][0], {'mocked-jwks': 'jwks'})
        self.assertEqual(mock_json_response.call_args[1]['status'], 200)
