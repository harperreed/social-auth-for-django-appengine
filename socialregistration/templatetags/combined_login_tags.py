"""
Created on 23.11.2010

@author: harperreed
"""
from django import template

register = template.Library()

@register.inclusion_tag('socialregistration/combined_login_extra.html')
def combined_login_extras():
    return {}
