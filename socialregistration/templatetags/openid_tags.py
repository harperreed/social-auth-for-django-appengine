"""
Created on 24.09.2009

@author: alen
"""
from django import template

register = template.Library()

@register.inclusion_tag('socialregistration/openid_form.html', takes_context = True)
def openid_form(context):
    request = context['request']
    return {'user': request.user }
