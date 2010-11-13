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


class AbstractSocialProfile(db.Model):
    internal_username = db.StringProperty()
    real_name = db.StringProperty()
    email = db.EmailProperty()
    pic_url = db.StringProperty()
    
        
    def get_internal_username(self):
        if not self.internal_username:
            self.internal_username = self.generate_internal_username()
        return self.internal_username
    
    def generate_internal_username(self, seed = False):
        """
        Eventually this should be looking at a base profile and pulling as much basic 
        information (first name, last name, email, etc) and parsing it accordingly.
        for now, it's some ugly thing like this.
        """
        username = ''
        username = self.real_name
        if not username:
            try:
                username = self.username
            except:
                pass
        if not username:
            username = self.email
        if not username:
            try:
                username = self.identity
            except:
                pass


        username = '%s%s'%(username,seed) if seed else username

        try:
            username = User.all().filter('username = ', username)[0]
        except: 
            return username
        else:
            seed = seed + 1 if seed else 1
            return self.generate_internal_username(seed=seed)

    
class FacebookProfile(AbstractSocialProfile):
    user = db.ReferenceProperty(User, collection_name="facebook_profiles")
    site = db.ReferenceProperty(Site, default=Site.objects.get_current())
    uid = db.StringProperty()
    username = db.StringProperty()
    
    
    
    def __unicode__(self):
        return '%s: %s' % (self.user, self.uid)
    
    def authenticate(self):
        return authenticate(uid=self.uid)
    
class TwitterProfile(AbstractSocialProfile):
    user = db.ReferenceProperty(User, collection_name="twitter_profiles")
    site = db.ReferenceProperty(Site, default=Site.objects.get_current())
    twitter_id =  db.IntegerProperty()
    username = db.StringProperty()

    def __unicode__(self):
        return '%s: %s' % (self.user, self.twitter_id)
    
    def authenticate(self):
        return authenticate(twitter_id=self.twitter_id)

class FriendFeedProfile(db.Model):
    user = db.ReferenceProperty(User)
    site = db.ReferenceProperty(Site, default=Site.objects.get_current())

class OpenIDProfile(AbstractSocialProfile):
    user = db.ReferenceProperty(User, collection_name="openid_profiles")
    site = db.ReferenceProperty(Site, default=Site.objects.get_current())
    identity = db.StringProperty()
    
    def authenticate(self):
        return authenticate(identity=self.identity)
    def get_internal_username(self):
#        return AbstractSocialProfile.get_internal_username(self)
        return super( OpenIDProfile, self).get_internal_username()




class OpenIDStore(db.Model):
    site = db.ReferenceProperty(Site, default=Site.objects.get_current())
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
    
