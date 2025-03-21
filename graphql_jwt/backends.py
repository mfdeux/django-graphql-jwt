from .shortcuts import get_user_and_org_by_token
from .utils import get_credentials, get_user_by_natural_key


class JSONWebTokenBackend(object):

    def authenticate(self, request=None, **kwargs):
        if request is None or getattr(request, '_jwt_token_auth', False):
            return None

        token = get_credentials(request, **kwargs)

        if token is not None:
            user, organization = get_user_and_org_by_token(token, request)
            request.organization = organization
            return user

        return None

    def get_user(self, user_id):
        return get_user_by_natural_key(user_id)
