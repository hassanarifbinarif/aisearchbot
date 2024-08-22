from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
import time
from asb.models import CandidateProfiles
from django.db.models import Q


def my_scheduled_job():
    try:
        profiles = CandidateProfiles.objects.all()

        for profile in profiles:
            print("start", profile)
            duplicate = CandidateProfiles.objects.filter(
                Q(person_linkedin_url=profile.person_linkedin_url) & 
                ~Q(id=profile.id), person_linkedin_url__isnull=False
            ).first()

            if duplicate:
                # Merge data from the current profile into the duplicate if fields are missing
                if duplicate.email1 is None and profile.email1:
                    duplicate.email1 = profile.email1
                if duplicate.email2 is None and profile.email2:
                    duplicate.email2 = profile.email2
                if duplicate.phone1 is None and profile.phone1:
                    duplicate.phone1 = profile.phone1
                if duplicate.phone2 is None and profile.phone2:
                    duplicate.phone2 = profile.phone2

                # Save the updated duplicate
                duplicate.save()

                # Delete the current profile after merging
                profile.delete()
            
            print("end")
            # Add a delay to prevent high CPU usage
            # time.sleep(2)
    except Exception as e:
        print('Inside Job ', e)


def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(my_scheduled_job, 'date', id='remove_duplicate_records_job')
    scheduler.start()