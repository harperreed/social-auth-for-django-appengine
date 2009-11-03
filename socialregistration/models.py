"""
Created on 22.09.2009

@author: alen
"""

#from django.db import models

# Create your models here.
from google.appengine.ext import db
from google.appengine.api import users

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
# Create your models here.


class FacebookProfile(db.Model):
    user = db.ReferenceProperty(User)
    site = db.ReferenceProperty(Site,)# default=Site.objects.get_current)
    uid = db.StringProperty()
    
    def __unicode__(self):
        return '%s: %s' % (self.user, self.uid)
    
    def authenticate(self):
        return authenticate(uid=self.uid)
    
class TwitterProfile(db.Model):
    user = db.ReferenceProperty(User)
    site = db.ReferenceProperty(Site,)# default=Site.objects.get_current)
    twitter_id =  db.IntegerProperty()
    
    def __unicode__(self):
        return '%s: %s' % (self.user, self.twitter_id)
    
    def authenticate(self):
        return authenticate(twitter_id=self.twitter_id)

class FriendFeedProfile(db.Model):
    user = db.ReferenceProperty(User)
    site = db.ReferenceProperty(Site,)# default=Site.objects.get_current)

class OpenIDProfile(db.Model):
    user = db.ReferenceProperty(User)
    site = db.ReferenceProperty(Site,)# default=Site.objects.get_current)
    identity = db.TextProperty()
    
    def authenticate(self):
        return authenticate(identity=self.identity)

class OpenIDStore(db.Model):
    site = db.ReferenceProperty(Site,)# default=Site.objects.get_current)
    server_url = db.StringProperty()
    handle = db.StringProperty()
    secret = db.TextProperty()
    issued =  db.IntegerProperty()
    lifetime =  db.IntegerProperty()
    assoc_type = db.TextProperty()

class OpenIDNonce(db.Model):
    server_url = db.StringProperty()
    timestamp =  db.IntegerProperty()
    salt = db.StringProperty()
    date_created =  db.DateTimeProperty(auto_now_add=True)
    
