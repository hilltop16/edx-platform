from common.djangoapps.util.json_request import JsonResponse
from django.conf import settings

def get_public_signing_jwks(request):
    jwt_dict = settings.JWT_AUTH
    if not jwt_dict.get('JWT_PUBLIC_SIGNING_JWK_SET'):
        return JsonResponse({'error': 'JWK set is not found'}, status=400)
    jwks = jwt_dict['JWT_PUBLIC_SIGNING_JWK_SET']
    return JsonResponse(jwks, status=200)