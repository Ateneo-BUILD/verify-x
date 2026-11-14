from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = 'accounts'

    def ready(self):
        from . import checks  # noqa: F401  (registers them)
        from . import django_bridge
        django_bridge.connect()
