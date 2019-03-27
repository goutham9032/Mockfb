# Note **: Add these default_app_config = 'app.apps.AppConfig' in __init__.py

from django.apps import AppConfig

class AppConfig(AppConfig):
    name = 'app'

    def ready(self):
        import app.signals
