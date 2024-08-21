from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.dispatch import receiver


class AsbConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'asb'

    def ready(self):
        import asb.tasks
        # Trigger the task after migrations are applied
        post_migrate.connect(trigger_task, sender=self)

    # def ready(self):
    #     from .jobs import start_scheduler
    #     start_scheduler()


@receiver(post_migrate)
def trigger_task(sender, **kwargs):
    from asb.tasks import merge_and_remove_duplicates
    merge_and_remove_duplicates.delay()