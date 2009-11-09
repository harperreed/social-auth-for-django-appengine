"""
Created on 22.09.2009

@author: alen
"""
from django.contrib.auth.models import User
from django.contrib.sites.models import Site

from google.appengine.ext import db

from socialregistration.models import (FacebookProfile, TwitterProfile,
    FriendFeedProfile, OpenIDProfile)

class Auth(object):
    def get_user(self, user_id):
        try:
            return db.get(user_id)
            #return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

class FacebookAuth(Auth):
    def authenticate(self, uid=None):
        try:
            facebook_profile = FacebookProfile.all()
            facebook_profile.filter('uid = ',uid)
            #facebook_profile.filter('site = ',Site.objects.get_current())
            facebook_profile = facebook_profile.fetch(1)
            auth_user = facebook_profile[0].user

            return auth_user
            #return FacebookProfile.objects.get(
            #    uid=uid,
            #    site=Site.objects.get_current()
            #).user
        except:
            return None

class TwitterAuth(Auth):
    def authenticate(self, twitter_id=None):
        try:
            twitter_profile = TwitterProfile.all()
            twitter_profile.filter('twitter_id = ',twitter_id)
            #twitter_profile.filter('site = ',Site.objects.get_current())
            twitter_profile = twitter_profile.fetch(1)
            auth_user = twitter_profile[0].user

            return auth_user
                #TwitterProfile.objects.get(
                #twitter_id=twitter_id,
                #site=Site.objects.get_current()
            #).user
        except:
            return None
        
class OpenIDAuth(Auth):
    def authenticate(self, identity=None):
        try:
            openid_profile = OpenIDProfile.all()
            openid_profile.filter('identity = ',identity)
            #openid_profile.filter('site = ',Site.objects.get_current())
            openid_profile = openid_profile.fetch(1)
            auth_user = openid_profile[0].user
            return auth_user

            #OpenIDProfile.objects.get(
            #    identity=identity,
                #site=Site.objects.get_current()
            #).user
        except:
            return None
