from django import template

register = template.Library()


def values_from_comma_separated_string(value):
    if not value:
        return ''
    try:
        result = [word.strip() for word in value.split(',')]
        return result
    except Exception as e:
        print(e)
        return ''
    

register.filter("values_from_comma_separated_string", values_from_comma_separated_string)