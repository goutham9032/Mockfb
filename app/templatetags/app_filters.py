#REF :http://www.pfinn.net/custom-django-filter-tutorial.html

# Django imports
from django import template
from datetime import date, timedelta

register = template.Library()

@register.filter(name='split_by')
def split_by(value, split_by):
    return value.split(split_by)

@register.filter(name='get_words_count')
def get_words_count(val):
    return len(val.split())
