from django.dispatch import Signal

token_issued = Signal(providing_args=['request', 'user', 'organization'])
token_refreshed = Signal(providing_args=['request', 'user', 'organization'])
