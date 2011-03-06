"""
Created on 22.09.2009

@author: alen
"""
import uuid
import sys
import md5

from django.conf import settings
from django.template import RequestContext
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.utils.translation import gettext as _
from django.http import HttpResponseRedirect

from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout as auth_logout
from django.contrib.sites.models import Site

from socialregistration.forms import UserForm
from socialregistration.utils import (OAuthClient, OAuthTwitter,
    OpenID, _https)
from socialregistration.models import FacebookProfile, TwitterProfile, OpenIDProfile

from facebook import Facebook
import urllib


FB_ERROR = _('We couldn\'t validate your Facebook credentials')

GENERATE_USERNAME = bool(getattr(settings, 'SOCIAL_GENERATE_USERNAME', getattr(
    settings, 'SOCIALREGISTRATION_GENERATE_USERNAME', False))) # SOCIAL_GENERATE_USERNAME will deprecate

def _get_next(request):
    """
    Returns a url to redirect to after the login
    """
    if 'next' in request.session:
        next = request.session['next']
        del request.session['next']
        return next
    elif 'next' in request.GET:
        return request.GET.get('next')
    elif 'next' in request.POST:
        return request.POST.get('next')
    else:
        return getattr(settings, 'LOGIN_REDIRECT_URL', '/')

def setup(request, template='socialregistration/setup.html', form_class=UserForm, extra_context=dict()):
    """
    Setup view to create a username & set email address after authentication
    """


    if 'socialregistration_profile' not in request.session:
        return HttpResponseRedirect(_get_next(request))

    
    if not GENERATE_USERNAME and False:
        # User can pick own username
        if not request.method == "POST":
            initial = {
               'username': request.session.pop('social_suggested_nickname',
                                               request.session.pop('social_suggested_username'), ''),
               'email': request.session.pop('social_suggested_email', ''),
            }
            form = form_class(
                request.session['socialregistration_user'],
                request.session['socialregistration_profile'],
                initial=initial,
            )
        else:
            form = form_class(
                request.session['socialregistration_user'],
                request.session['socialregistration_profile'],
                request.POST
            )
            if form.is_valid():
                form.save()
                user = form.profile.authenticate()
                login(request, user)

                del request.session['socialregistration_user']
                del request.session['socialregistration_profile']

                return HttpResponseRedirect(_get_next(request))

        extra_context.update(dict(form=form))

        return render_to_response(
            template,
            extra_context,
            context_instance=RequestContext(request)
        )
    else:
    
        # Generate user and profile
        user = request.session['socialregistration_user']
        
        
        user.username = str(uuid.uuid4())[:30]
        if request.session['social_suggested_username']:
            user.username = request.session['social_suggested_username']

        user.save()

        profile = request.session['socialregistration_profile']
        profile.user = user
        profile.save()

        if profile.email:
            user.email = profile.email
            user.save()
	if profile.realname:
	    user.firstname = profile.realname.partition(' ')[0]
	    user.lastname = profile.realname.partition(' ')[2]
	    user.save()

        # Authenticate and login
        user = profile.authenticate()
        login(request, user)

        # Clear & Redirect
        if 'socialregistration_user' in request.session:
            del request.session['socialregistration_user']
        if 'socialregistration_profile' in request.session:
            del request.session['socialregistration_profile']
        return HttpResponseRedirect(_get_next(request))


def facebook_login(request, template='socialregistration/facebook.html', extra_context=dict(), account_inactive_template='socialregistration/account_inactive.html'):
    """
    View to handle the Facebook login
    """
    fb = Facebook(settings.FACEBOOK_API_KEY, settings.FACEBOOK_SECRET_KEY)
    if not fb.check_session(request):

        facebook_url = "http://www.facebook.com/login.php?"

        extra_context.update(
            dict(error=FB_ERROR)
        )

        args = {
            "api_key": settings.FACEBOOK_API_KEY,
            "v": "1.0",
            "fbconnect": "true",
            "display": "page",
            "next":request.build_absolute_uri( _get_next(request)),
            "return_session": "true",
        }


        #if extended_permissions:
        #    if isinstance(extended_permissions, basestring):
        #        extended_permissions = [extended_permissions]
        #    args["req_perms"] = ",".join(extended_permissions)
        #self.redirect("http://www.facebook.com/login.php?" +
        #              urllib.urlencode(args))

        facebook_url = facebook_url + urllib.urlencode(args) 

        return HttpResponseRedirect(facebook_url)



        return render_to_response(
            template, extra_context, context_instance=RequestContext(request)
        )

    user = authenticate(uid=str(fb.uid))

    if user is None:
        user = authenticate(uid=fb.uid)
        fb_profile = fb.users.getInfo(fb.uid, ['name','email','pic_square','username', ])[0]
        request.session['social_suggested_username'] = fb_profile['username']
        request.session['socialregistration_profile'] = FacebookProfile(
            uid=fb.uid,
            username = fb_profile['username'],
            real_name = fb_profile['name'],
            email = fb_profile['email'],
            pic_url = fb_profile['pic_square'],
        )
        request.session['socialregistration_user'] = User(username=''.join(fb_profile['name'].split(' ')[:2]))
        request.session['next'] = _get_next(request)
 
        return HttpResponseRedirect(reverse('socialregistration_setup'))

    if not user.is_active:
        return render_to_response(
            account_inactive_template,
            extra_context,
            context_instance=RequestContext(request)
        )

    login(request, user)

    return HttpResponseRedirect(_get_next(request))

def facebook_connect(request, template='socialregistration/facebook.html', extra_context=dict()):
    """
    View to handle connecting existing accounts with facebook
    """
    fb = Facebook(settings.FACEBOOK_API_KEY, settings.FACEBOOK_SECRET_KEY)
    if not fb.check_session(request) \
        or not request.user.is_authenticated():
        extra_context.update(
            dict(error=FB_ERROR)
        )
        return render_to_response(
            template,
            extra_context,
            context_instance=RequestContext(request)
        )

    try:
        profile = FacebookProfile.all().filter('uid=',fb.uid).fetch(1)[0]
    except IndexError:
        fb_profile = fb.users.getInfo(fb.uid, ['name','email','pic_square','username', ])[0]
        profile = FacebookProfile(user=request.user,
            uid=fb.uid,
            username = fb_profile['username'],
            real_name = fb_profile['name'],
            email = fb_profile['email'],
            pic_url = fb_profile['pic_square'],
            )
        profile.save()


    return HttpResponseRedirect(_get_next(request))

def logout(request, redirect_url=None):
    """
    Logs the user out of django. This is only a wrapper around
    django.contrib.auth.logout. Logging users out of Facebook for instance
    should be done like described in the developer wiki on facebook.
    http://wiki.developers.facebook.com/index.php/Connect/Authorization_Websites#Logging_Out_Users
    """
    auth_logout(request)

    url = redirect_url or getattr(settings, 'LOGOUT_REDIRECT_URL', '/')

    return HttpResponseRedirect(url)

def twitter(request, account_inactive_template='socialregistration/account_inactive.html', extra_context=dict()):
    """
    Actually setup/login an account relating to a twitter user after the oauth
    process is finished successfully
    """
    client = OAuthTwitter(
        request, settings.TWITTER_CONSUMER_KEY,
        settings.TWITTER_CONSUMER_SECRET_KEY,
        settings.TWITTER_REQUEST_TOKEN_URL,
    )

    user_info = client.get_user_info()

    if request.user.is_authenticated():
        # Handling already logged in users connecting their accounts
        try:
            profile = TwitterProfile.all().filter('twitter_id = ',user_info['id']).fetch(1)[0]
        except IndexError: # There can only be one profile!
            profile = TwitterProfile(user=request.user, 
                twitter_id=user_info['id'], 
                username=user_info['screen_name'], 
                real_name=user_info['name'],
                pic_url = user_info['profile_image_url'],
            )
            profile.save()

        return HttpResponseRedirect(_get_next(request))

    user = authenticate(twitter_id=user_info['id'])

    if user is None:
        profile = TwitterProfile(                
            twitter_id=user_info['id'], 
            username=user_info['screen_name'], 
            real_name=user_info['name'],
            pic_url = user_info['profile_image_url'],
        )

        user = User(username=profile.real_name)
        request.session['social_suggested_username'] = user_info['screen_name']
        request.session['socialregistration_profile'] = profile
        request.session['socialregistration_user'] = user
        request.session['next'] = _get_next(request)
        return HttpResponseRedirect(reverse('socialregistration_setup'))

    if not user.is_active:
        return render_to_response(
            account_inactive_template,
            extra_context,
            context_instance=RequestContext(request)
        )

    login(request, user)

    return HttpResponseRedirect(_get_next(request))

def friendfeed(request):
    """
    Actually setup an account relating to a friendfeed user after the oauth process
    is finished successfully
    """
    raise NotImplementedError()

def oauth_redirect(request, consumer_key=None, secret_key=None, request_token_url=None, access_token_url=None, authorization_url=None, callback_url=None, parameters=None):
    """
    View to handle the OAuth based authentication redirect to the service provider
    """
    request.session['next'] = _get_next(request)
    client = OAuthClient(request, consumer_key, secret_key,
        request_token_url, access_token_url, authorization_url, callback_url, parameters)
    return client.get_redirect()

def oauth_callback(request, consumer_key=None, secret_key=None, request_token_url=None, access_token_url=None, authorization_url=None, callback_url=None, template='socialregistration/oauthcallback.html', extra_context=dict(), parameters=None):
    """
    View to handle final steps of OAuth based authentication where the user
    gets redirected back to from the service provider
    """
    client = OAuthClient(request, consumer_key, secret_key, request_token_url,
        access_token_url, authorization_url, callback_url, parameters)

    extra_context.update(dict(oauth_client=client))

    if not client.is_valid():
        return render_to_response(
            template, extra_context, context_instance=RequestContext(request)
        )

    # We're redirecting to the setup view for this oauth service
    return HttpResponseRedirect(reverse(client.callback_url))

def openid_redirect(request):
    """
    Redirect the user to the openid provider
    """
    request.session['next'] = _get_next(request)
    request.session['openid_provider'] = request.GET.get('openid_provider')

    client = OpenID(
        request,
        'http%s://%s%s' % (
            _https(),
            Site.objects.get_current().domain,
            reverse('openid_callback')
        ),
        request.GET.get('openid_provider')
    )
    return client.get_redirect()

def openid_callback(request, template='socialregistration/openid.html', extra_context=dict(), account_inactive_template='socialregistration/account_inactive.html'):
    """
    Catches the user when he's redirected back from the provider to our site
    """
    client = OpenID(
        request,
        'http%s://%s%s' % (
            _https(),
            Site.objects.get_current().domain,
            reverse('openid_callback')
        ),
        request.session.get('openid_provider')
    )
#    print 'hi'
#    print request.GET
    if client.is_valid():
        if request.user.is_authenticated():
            # Handling already logged in users just connecting their accounts
            try:
                profile = OpenIDProfile.all().filter('identity=',request.GET.get('openid.claimed_id')).fetch(1)[0]
            except IndexError: # There can only be one profile with the same identity
                profile = OpenIDProfile(
                    user = request.user,
                    identity=request.GET.get('openid.claimed_id'),
                    real_name=request.GET.get('openid.ax.value.fullname'),
                    username=request.GET.get('openid.ax.value.nickname'),
                    email=request.GET.get('openid.ax.value.email'),
                    pic_url=request.GET.get('openid.ax.value.image'),
                )
                profile.save()

            return HttpResponseRedirect(_get_next(request))

        user = authenticate(identity=request.GET.get('openid.claimed_id'))
        if user is None:
            user = User(username='openid')
            request.session['social_suggested_username'] = request.GET.get('openid.ax.value.nickname')
            request.session['socialregistration_user'] = user
            if request.GET.get('openid.ext2.value.email'):
                request.session['social_suggested_username'] = request.GET.get('openid.ext2.value.email').split('@')[0]
                request.session['socialregistration_profile'] = OpenIDProfile(
                    identity=request.GET.get('openid.claimed_id'),
                    internal_username=request.session['social_suggested_username'],
                    email=request.GET.get('openid.ext2.value.email'),
                    pic_url= "http://www.gravatar.com/avatar/" + md5.md5(request.GET.get('openid.ext2.value.email')).hexdigest() ,
                )
            elif request.GET.get('openid.sreg.email'):
                request.session['social_suggested_username'] = request.GET.get('openid.sreg.nickname')
                request.session['socialregistration_profile'] = OpenIDProfile(
                    identity=request.GET.get('openid.claimed_id'),
                    real_name=request.GET.get('openid.sreg.fullname'),
                    internal_username=request.GET.get('openid.sreg.nickname'),
                    email=request.GET.get('openid.sreg.email'),
                    pic_url="http://www.gravatar.com/avatar/" + md5.md5(request.GET.get('openid.sreg.email')).hexdigest(),
                )
            elif request.GET.get('openid.ext1.value.email'):
                request.session['social_suggested_username'] = request.GET.get('openid.ext1.value.email').split('@')[0]
                request.session['socialregistration_profile'] = OpenIDProfile(
                    identity=request.GET.get('openid.claimed_id'),
                    internal_username=request.session['social_suggested_username'],
                    email=request.GET.get('openid.ext1.value.email'),
                    pic_url= "http://www.gravatar.com/avatar/" + md5.md5(request.GET.get('openid.ext1.value.email')).hexdigest() ,
                )
            else:
                request.session['socialregistration_profile'] = OpenIDProfile(
                    identity=request.GET.get('openid.claimed_id'),
                    real_name=request.GET.get('openid.ax.value.fullname'),
                    internal_username=request.GET.get('openid.ax.value.nickname'),
                    email=request.GET.get('openid.ax.value.email'),
                    pic_url=request.GET.get('openid.ax.value.image'),
                )
            for key, value in getattr(client, 'registration_data', {}).items():
                request.session['social_suggested_%s' % key] = value

            return HttpResponseRedirect(reverse('socialregistration_setup'))
        else:
            login(request, user)
            return HttpResponseRedirect(_get_next(request))

        if not user.is_active:
            return render_to_response(
                account_inactive_template,
                extra_context,
                context_instance=RequestContext(request)
            )

        login(request, user)
        return HttpResponseRedirect(_get_next(request))            
    
    return render_to_response(
        template,
        dict(),
        context_instance=RequestContext(request)
    )

def combined_login(request,  template='socialregistration/login_form.html'):
    if request.POST:
        openid_identifier = request.POST.get('openid_identifier', None)
        if openid_identifier =='facebook_connect':
            return HttpResponseRedirect(reverse('facebook_login'))
        if openid_identifier =='twitter_oauth':
            return HttpResponseRedirect(reverse('twitter_redirect') )
        # i think you can push the GET params in the reverse function
        return HttpResponseRedirect(reverse('openid_redirect') + "?openid_provider="+ openid_identifier)
    else:
        return render_to_response(
            template, context_instance=RequestContext(request)
        )
