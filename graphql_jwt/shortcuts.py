from .refresh_token.shortcuts import create_refresh_token, get_refresh_token
from .settings import jwt_settings
from .utils import get_payload, get_user_and_org_by_payload

__all__ = [
    'get_token',
    'get_user_and_org_by_token',
    'get_refresh_token',
    'create_refresh_token',
]


def get_token(user, organization, context=None, **extra):
    payload = jwt_settings.JWT_PAYLOAD_HANDLER(user, organization, context)
    payload.update(extra)
    return jwt_settings.JWT_ENCODE_HANDLER(payload, context)


def get_user_and_org_by_token(token, context=None):
    payload = get_payload(token, context)
    return get_user_and_org_by_payload(payload)
