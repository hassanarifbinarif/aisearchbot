# myapp/tasks.py
from celery import shared_task
from asb.models import CandidateProfiles
from django.db.models import Q

@shared_task
def merge_and_remove_duplicates():
    profiles = CandidateProfiles.objects.filter(person_linkedin_url__isnull=False).order_by('id')
    
    for profile in profiles:
        try:
                
            duplicate = CandidateProfiles.objects.filter(
                Q(person_linkedin_url=profile.person_linkedin_url) & 
                ~Q(id=profile.id)
            ).first()
            print("start", profile)

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
        except Exception as e:
            print(e)

    print("Profile processing completed.")
        
