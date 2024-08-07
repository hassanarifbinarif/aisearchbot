import re
from functools import reduce
from operator import or_
from django.db.models import Q, F, Value, IntegerField, Count, When, Case, Func, Max



class ArrayLength(Func):
    function = 'array_length'
    template = '%(function)s(%(expressions)s, 1)'
    output_field = IntegerField()


class ArrayToString(Func):
    function = 'ARRAY_TO_STRING'
    template = "%(function)s(%(expressions)s, ' ')"


def build_regex_pattern(keyword):
    # return rf'(?i)(?<!\w){re.escape(keyword)}(?!\w)'
    escaped_keyword = re.escape(keyword)
    return rf'(?i)(?<!\w)(?<![a-zA-Z0-9_]){escaped_keyword}(?![a-zA-Z0-9_])(?!\w)'


def search_skills(skills, queryset):
    max_length = queryset.aggregate(max_length=Max(ArrayLength(F('person_skills'))))['max_length'] or 0

    # Annotate with skills_string
    queryset = queryset.annotate(skills_string=ArrayToString('person_skills'))

    # Create a Case for each position and skill
    cases = []
    for position in range(max_length):
        for skill_index, skill in enumerate(skills):
            cases.append(
                When(
                    Q(skills_string__regex=build_regex_pattern(skill)) &
                    Q(person_skills__len__gt=position) &
                    Q(**{f'person_skills__{position}__regex': build_regex_pattern(skill)}),
                    then=Value(position * 1000 + skill_index)
                )
            )

    # Annotate with priority
    queryset = queryset.annotate(
        priority=Case(*cases, default=Value(1000000), output_field=IntegerField())
    )

    # Filter to include only profiles with at least one matching skill
    skill_filter = reduce(or_, [Q(skills_string__regex=build_regex_pattern(skill)) for skill in skills])
    queryset = queryset.filter(skill_filter)

    # Order by priority
    queryset = queryset.order_by('priority', '-id')

    return queryset


def keyword_with_job_title_or_skill(queryset, keywords, job_titles, skills):
    # qs = queryset
    # if len(skills) > 0:
    #     qs = search_skills(skills, queryset)


    master_keyword_regex = build_regex_pattern(keywords)
    job_title_keyword_patterns = [build_regex_pattern(kw) for kw in job_titles]

    # Create a Q object for job title keywords
    primary_job_title_q = Q()
    for pattern in job_title_keyword_patterns:
        primary_job_title_q &= Q(headline__regex=pattern) | Q(current_position__regex=pattern)

    # Create a Q object for job title keywords using OR (Secondary Criteria)
    secondary_job_title_q = Q()
    for pattern in job_title_keyword_patterns:
        secondary_job_title_q |= Q(headline__regex=pattern) | Q(current_position__regex=pattern)

    # Filter profiles based on job title containing "Angular" and all job title keywords

    filtered_profiles = queryset.annotate(
        job_title_match=Case(
            When((Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & primary_job_title_q, then=Value(1)),
            When((Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & secondary_job_title_q, then=Value(2)),
            default=Value(0),
            output_field=IntegerField()
        )
    )

    # filtered_profiles = queryset.filter(
    #     (Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & job_title_q
    # )

    # Annotate profiles with the position of each skill
    max_length = filtered_profiles.aggregate(max_length=Max(ArrayLength(F('person_skills'))))['max_length'] or 0

    cases = []
    priority = 1

    for skill in skills:
        skill_regex = build_regex_pattern(skill)
        for position in range(max_length):
            cases.append(
                When(
                    Q(**{f'person_skills__{position}__regex': skill_regex}),
                    then=Value(priority)
                )
            )
            priority += 1

    # Annotate profiles with skill position priority
    filtered_profiles = filtered_profiles.annotate(
        skill_priority=Case(
            *cases,
            default=Value(999999),
            output_field=IntegerField()
        )
    )

    # Annotate profiles with parent_priority for primary criteria
    filtered_profiles = filtered_profiles.annotate(
        parent_priority=Case(
            When(job_title_match=1, then=Value(1)),
            When(job_title_match=2, then=Value(2)),
            default=Value(999999),
            output_field=IntegerField()
        )
        # parent_priority=Value(1, output_field=IntegerField())
    )

    # Order profiles by skill priority and id
    filtered_profiles = filtered_profiles.order_by('parent_priority', 'job_title_match', 'skill_priority', '-id')

    what = filtered_profiles.filter(parent_priority=1).count()
    print(what)

    wh = filtered_profiles.filter(parent_priority=2).count()
    print(wh)
    
    # return qs
    return filtered_profiles





















# master_keyword_regex = build_regex_pattern(keywords)
#     job_title_keyword_patterns = [build_regex_pattern(kw) for kw in job_titles]

#     # Create a Q object for job title keywords
#     job_title_q = Q()
#     for pattern in job_title_keyword_patterns:
#         job_title_q &= Q(headline__regex=pattern) | Q(current_position__regex=pattern)

#     # Filter profiles based on job title containing "Angular" and all job title keywords

#     filtered_profiles = queryset.annotate(
#         job_title_match=Case(
#             When((Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & job_title_q, then=Value(True)),
#             default=Value(False),
#             output_field=IntegerField()
#         )
#     )

#     # filtered_profiles = queryset.filter(
#     #     (Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & job_title_q
#     # )

#     # Annotate profiles with the position of each skill
#     max_length = filtered_profiles.aggregate(max_length=Max(ArrayLength(F('person_skills'))))['max_length'] or 0

#     cases = []
#     priority = 1

#     for skill in skills:
#         skill_regex = build_regex_pattern(skill)
#         for position in range(max_length):
#             cases.append(
#                 When(
#                     Q(**{f'person_skills__{position}__regex': skill_regex}),
#                     then=Value(priority)
#                 )
#             )
#             priority += 1

#     # Annotate profiles with skill position priority
#     filtered_profiles = filtered_profiles.annotate(
#         skill_priority=Case(
#             *cases,
#             default=Value(999999),
#             output_field=IntegerField()
#         )
#     )

#     # Annotate profiles with parent_priority for primary criteria
#     filtered_profiles = filtered_profiles.annotate(
#         parent_priority=Value(1, output_field=IntegerField())
#     )

#     # Order profiles by skill priority and id
#     filtered_profiles = filtered_profiles.order_by('parent_priority', '-job_title_match', 'skill_priority', '-id')
    
#     # return qs
#     return filtered_profiles