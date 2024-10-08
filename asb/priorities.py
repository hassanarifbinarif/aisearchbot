import re
import operator
from functools import reduce
from operator import or_
from django.db.models import Q, F, Value, IntegerField, Count, When, Case, Func, Max, TextField
from django.db.models.functions import Coalesce, Concat



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

    master_keyword_regex = build_regex_pattern(keywords)
    job_title_keyword_patterns = [build_regex_pattern(kw) for kw in job_titles]

    # Create a Q object for job title keywords using AND (Primary Criteria)
    primary_job_title_q = Q(pk__isnull=False)  # Default to a no-op Q object that always evaluates to True
    if job_title_keyword_patterns:
        primary_job_title_q = Q()  # Reinitialize only if there are patterns
        for pattern in job_title_keyword_patterns:
            primary_job_title_q &= Q(headline__regex=pattern) | Q(current_position__regex=pattern)

    # Create a Q object for job title keywords using OR (Secondary Criteria)
    secondary_job_title_q = Q(pk__isnull=False)  # Default to a no-op Q object that always evaluates to True
    if job_title_keyword_patterns:
        secondary_job_title_q = Q()  # Reinitialize only if there are patterns
        for pattern in job_title_keyword_patterns:
            secondary_job_title_q |= Q(headline__regex=pattern) | Q(current_position__regex=pattern)

    filtered_profiles = queryset.annotate(
        job_title_match=Case(
            When((Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & primary_job_title_q, then=Value(1)),
            When((Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & secondary_job_title_q, then=Value(2)),
            When(primary_job_title_q, then=Value(4)),
            When(secondary_job_title_q, then=Value(5)),
            When(Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex), then=Value(6)),
            default=Value(0),
            output_field=IntegerField()
        )
    )

    filtered_profiles = filtered_profiles.annotate(
        # Tertiary AND: Master keyword AND all job title keywords
        tertiary_and_match=Case(
            When(
                (Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & primary_job_title_q,
                # reduce(operator.and_, [Q(headline__regex=kw) | Q(current_position__regex=kw) for kw in job_title_keyword_patterns]),
                then=Value(1)
            ),
            default=Value(0),
            output_field=IntegerField()
        ),
        
        # Tertiary OR: Master keyword AND any of the job title keywords
        tertiary_or_match=Case(
            When(
                (Q(headline__regex=master_keyword_regex) | Q(current_position__regex=master_keyword_regex)) & secondary_job_title_q,
                # reduce(operator.or_, [Q(headline__regex=kw) | Q(current_position__regex=kw) for kw in job_title_keyword_patterns]),
                then=Value(2)
            ),
            default=Value(0),
            output_field=IntegerField()
        )
    )

    if skills:
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

        filtered_profiles = filtered_profiles.annotate(
            skill_priority=Case(
                *cases,
                default=Value(999999),
                output_field=IntegerField()
            )
        )
    else:
        filtered_profiles = filtered_profiles.annotate(
            skill_priority=Value(999999, output_field=IntegerField())
        )

    # Annotate profiles with parent_priority for primary criteria
    filtered_profiles = filtered_profiles.annotate(
        parent_priority=Case(
            When(job_title_match=1, then=Value(1)),
            When(job_title_match=2, then=Value(2)),
            When(job_title_match=4, then=Value(4)),
            When(job_title_match=5, then=Value(5)),
            When(job_title_match=6, then=Value(6)),
            # When(tertiary_and_match=1, then=Value(3)),
            # When(tertiary_or_match=2, then=Value(4)),
            default=Value(999999),
            output_field=IntegerField()
        )
        # parent_priority=Value(1, output_field=IntegerField())
    )

    # Order profiles by skill priority and id
    filtered_profiles = filtered_profiles.order_by('parent_priority', 'job_title_match', 'skill_priority', '-id')

    # n1 = filtered_profiles.filter(parent_priority=1).count()
    # print(n1)

    # n2 = filtered_profiles.filter(parent_priority=2).count()
    # print(n2)

    # n4 = filtered_profiles.filter(parent_priority=4).count()
    # print(n4)

    # n5 = filtered_profiles.filter(parent_priority=5).count()
    # print(n5)

    # n6 = filtered_profiles.filter(parent_priority=6).count()
    # print(n6)
    
    # return qs
    return filtered_profiles


# --------------------------------------------------------------


def boolean_keyword_with_job_title_or_skill(queryset, query, job_titles, skills):
    """
    Perform a prioritized search based on the boolean query.
    """

    queryset = queryset.annotate(job_title=Concat('headline', Value(' '), 'current_position', output_field=TextField()))

    keyword_fields = ['headline', 'current_position']
    master_keyword_regex = boolean_search(query, ['job_title'])
    # print(master_keyword_regex)
    job_title_keyword_patterns = [build_regex_pattern(kw) for kw in job_titles]

    primary_job_title_q = Q(pk__isnull=False)
    if job_title_keyword_patterns:
        primary_job_title_q = Q()
        for pattern in job_title_keyword_patterns:
            primary_job_title_q &= Q(headline__regex=pattern) | Q(current_position__regex=pattern)

    secondary_job_title_q = Q(pk__isnull=False)
    if job_title_keyword_patterns:
        secondary_job_title_q = Q()
        for pattern in job_title_keyword_patterns:
            secondary_job_title_q |= Q(headline__regex=pattern) | Q(current_position__regex=pattern)
    

    is_two_operator_query = has_only_two_top_level_operators(query)
    if is_two_operator_query:
        and_query, or_query = create_and_or_queries(query, ['job_title'])
        print(and_query)
        print(or_query)
        filtered_profiles = queryset.annotate(
            job_title_match=Case(
                When((Q(and_query)) & primary_job_title_q, then=Value(1)),
                When((Q(or_query)) & secondary_job_title_q, then=Value(2)),
                When((Q(and_query)), then=Value(3)),
                When((Q(or_query)), then=Value(4)),
                default=Value(0),
                output_field=IntegerField()
            )
        )
    else:
        filtered_profiles = queryset.annotate(
            job_title_match=Case(
                When((Q(master_keyword_regex)) & primary_job_title_q, then=Value(1)),
                When((Q(master_keyword_regex)) & secondary_job_title_q, then=Value(2)),
                When((Q(master_keyword_regex)), then=Value(3)),
                default=Value(0),
                output_field=IntegerField()
            )
        )

    if skills:
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

        filtered_profiles = filtered_profiles.annotate(
            skill_priority=Case(
                *cases,
                default=Value(999999),
                output_field=IntegerField()
            )
        )
    else:
        filtered_profiles = filtered_profiles.annotate(
            skill_priority=Value(999999, output_field=IntegerField())
        )

    filtered_profiles = filtered_profiles.annotate(
        parent_priority=Case(
            When(job_title_match=1, then=Value(1)),
            When(job_title_match=2, then=Value(2)),
            When(job_title_match=3, then=Value(3)),
            When(job_title_match=4, then=Value(4)),
            default=Value(999999),
            output_field=IntegerField()
        )
    )

    
    filtered_profiles = filtered_profiles.order_by('parent_priority', 'job_title_match', 'skill_priority', '-id')

    # n1 = filtered_profiles.filter(parent_priority=1).count()
    # print(n1)

    # n2 = filtered_profiles.filter(parent_priority=2).count()
    # print(n2)

    # n3 = filtered_profiles.filter(parent_priority=3).count()
    # print(n3)

    # n4 = filtered_profiles.filter(parent_priority=4).count()
    # print(n4)
    
    return filtered_profiles


def tokenize(query):
    """
    Tokenizes the input query, handling quoted phrases and logical operators.
    """
    tokens = []
    i = 0
    length = len(query)
    while i < length:
        if query[i] in '()"':
            if query[i] == '"':
                end_quote = query.find('"', i + 1)
                if end_quote == -1:
                    end_quote = length
                tokens.append(query[i:end_quote + 1])
                i = end_quote + 1
            else:
                tokens.append(query[i])
                i += 1
        elif query[i].isspace():
            i += 1
        else:
            end = i
            while end < length and not query[end].isspace() and query[end] not in '()"':
                end += 1
            tokens.append(query[i:end])
            i = end
    return tokens


def boolean_search(query, fields):
    """
    Parse the boolean search query and construct a Q object for Django ORM.
    Accepts a list of fields to apply the query on.
    """
    # Tokenize the query
    tokens = tokenize(query)
    
    # Initialize an empty Q object
    q = Q()

    # Stack for grouping
    stack = []
    
    # Current operator context
    current_op = Q.__and__

    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token.upper() == 'AND':
            current_op = Q.__and__
        elif token.upper() == 'OR':
            current_op = Q.__or__
        elif token.upper() == 'NOT':
            next_token = tokens[i + 1]
            i += 1
            sub_q = Q()
            if next_token.startswith('"') and next_token.endswith('"'):
                exact_phrase = next_token.strip('"')
                for field in fields:
                    regex_pattern = build_regex_pattern(exact_phrase)
                    sub_q |= Q(**{f"{field}__regex": regex_pattern})
            else:
                for field in fields:
                    regex_pattern = build_regex_pattern(next_token)
                    sub_q |= Q(**{f"{field}__regex": regex_pattern})
            q &= ~sub_q
        elif token == '(':
            stack.append((q, current_op))
            q = Q()
            current_op = Q.__and__
        elif token == ')':
            if stack:
                prev_q, prev_op = stack.pop()
                q = prev_op(prev_q, q)
            current_op = Q.__and__
        elif token.startswith('"') and token.endswith('"'):
            exact_phrase = token.strip('"')
            sub_q = Q()
            for field in fields:
                regex_pattern = build_regex_pattern(exact_phrase)
                sub_q |= Q(**{f"{field}__regex": regex_pattern})
            q = current_op(q, sub_q)
        else:
            if token.upper() not in ['AND', 'OR', 'NOT']:
                sub_q = Q()
                for field in fields:
                    regex_pattern = build_regex_pattern(token)
                    sub_q |= Q(**{f"{field}__regex": regex_pattern})
                q = current_op(q, sub_q)
        
        i += 1

    return q


def has_only_two_top_level_operators(query):
    """
    Check if the query contains only two operators at the topmost level.
    Operators include AND, OR, and NOT.
    Returns True if there are only two operators, False otherwise.
    """
    tokens = tokenize(query)
    top_level_operators = []
    parentheses_level = 0
    
    for token in tokens:
        if token == '(':
            parentheses_level += 1
        elif token == ')':
            parentheses_level -= 1
        elif parentheses_level == 0 and token.upper() in ['AND', 'OR', 'NOT']:
            top_level_operators.append(token.upper())

    return len(top_level_operators) == 2



def parse_query(query):
    tokens = re.findall(r'\(|\)|AND|OR|NOT|"[^"]+"|\b\w+\b', query)
    return tokens

def build_query(terms, operator, fields):
    query = Q()
    # print(f"Building query with terms: {terms} and operator: {operator}")
    for term in terms:
        sub_query = Q()
        if isinstance(term, str):
            for field in fields:
                sub_query |= Q(**{f"{field}__icontains": term.strip('"')})
            if operator == 'AND':
                query &= sub_query
            elif operator == 'OR':
                query |= sub_query
        else:
            print(f"Unexpected term type: {type(term)}")
    return query

def create_and_or_queries(query, fields):
    tokens = parse_query(query)
    
    # print(f"Tokens: {tokens}")
    
    and_terms = []
    or_terms = []
    current_terms = []
    current_operator = None
    
    stack = []
    
    for token in tokens:
        if token.upper() == 'AND':
            if current_operator == 'OR':
                or_terms.append(current_terms)
                current_terms = []
            current_operator = 'AND'
        elif token.upper() == 'OR':
            if current_operator == 'AND':
                and_terms.append(current_terms)
                current_terms = []
            current_operator = 'OR'
        elif token == '(':
            stack.append((current_terms, current_operator))
            current_terms = []
            current_operator = None
        elif token == ')':
            if current_operator == 'AND':
                and_terms.append(current_terms)
            elif current_operator == 'OR':
                or_terms.append(current_terms)
            current_terms, current_operator = stack.pop()
            if current_operator == 'AND':
                current_terms.append(build_query(and_terms, 'AND', fields))
                and_terms = []
            elif current_operator == 'OR':
                current_terms.append(build_query(or_terms, 'OR', fields))
                or_terms = []
        else:
            current_terms.append(token)
    
    if current_terms:
        if current_operator == 'AND':
            and_terms.append(current_terms)
        elif current_operator == 'OR':
            or_terms.append(current_terms)
    
    # print(f"and_terms: {and_terms}")
    # print(f"or_terms: {or_terms}")
    
    # Flatten terms before creating the final query
    and_query = build_query([term for sublist in and_terms for term in (sublist if isinstance(sublist, list) else [sublist])], 'AND', fields) if and_terms else Q()
    or_query = build_query([term for sublist in or_terms for term in (sublist if isinstance(sublist, list) else [sublist])], 'OR', fields) if or_terms else Q()

    # print(f"and_query: {and_query}")
    # print(f"or_query: {or_query}")
    
    return and_query, or_query