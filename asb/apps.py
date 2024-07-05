from django.apps import AppConfig


class AsbConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'asb'

    def ready(self):
        # Import the custom lookup to ensure it is registered
        import asb.lookups
