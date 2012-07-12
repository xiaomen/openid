
"""
This module implements an example server for the OpenID library.  Some
functionality has been omitted intentionally; this code is intended to
be instructive on the use of this library.  This server does not
perform actual user authentication and serves up only one OpenID URL,
with the exception of IDP-generated identifiers.

Some code conventions used here:

* 'request' is a Django request object.

* 'openid_request' is an OpenID library request object.

* 'openid_response' is an OpenID library response
"""

import cgi
import json
import pickle
import base64
import logging

from django import http
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.views.generic.simple import direct_to_template

from djopenid import util
from djopenid.util import getViewURL
from djopenid.server.models import AuthSites

from openid.server.server import Server, ProtocolError, CheckIDRequest, \
     EncodingError
from openid.server.trustroot import verifyReturnTo
from openid.yadis.discover import DiscoveryFailure
from openid.consumer.discover import OPENID_IDP_2_0_TYPE
from openid.extensions import sreg
from openid.extensions import pape
from openid.fetchers import HTTPFetchingError

logger = logging.getLogger()

def getOpenIDStore():
    """
    Return an OpenID store object fit for the currently-chosen
    database backend, if any.
    """
    return util.getOpenIDStore('/tmp/djopenid_s_store', 's_')

def getServer(request):
    """
    Get a Server object to perform OpenID authentication.
    """
    return Server(getOpenIDStore(), getViewURL(request, endpoint))

def setRequest(request, openid_request):
    """
    Store the openid request information in the session.
    """
    if openid_request:
        request.session['openid_request'] = openid_request
    else:
        request.session['openid_request'] = None

def getRequest(request):
    """
    Get an openid request from the session, if any.
    """
    return request.session.get('openid_request')

def server(request):
    return http.HttpResponseRedirect('/admin')

def idpXrds(request):
    """
    Respond to requests for the IDP's XRDS document, which is used in
    IDP-driven identifier selection.
    """
    return util.renderXRDS(
        request, [OPENID_IDP_2_0_TYPE], [getViewURL(request, endpoint)])

def idPage(request, user):
    """
    Serve the identity page for OpenID URLs.
    """
    return direct_to_template(
            request,
            'server/idPage.html',
            {'server_url': getViewURL(request, endpoint)})

def trustPage(request):
    """
    Display the trust page template, which allows the user to decide
    whether to approve the OpenID verification.
    """
    return direct_to_template(
        request,
        'server/trust.html',
        {'trust_handler_url':getViewURL(request, processTrustResult)})

def endpoint(request):
    """
    Respond to low-level OpenID protocol messages.
    """
    ret_json = request.META.get('HTTP_ACCEPT', False) and \
            not (request.META['HTTP_ACCEPT'].find('html') > -1)
    logger.info(request.META)
    logger.info(ret_json)

    query = util.normalDict(request.GET or request.POST)
    if query.get('data', ''):
        #TODO no use query.get('remember', '')
        user = authenticate(username=query.get('user'), password=query.get('passwd'))
        if not user or not user.is_active:
            next_url = query.get('next') or request.META.get('HTTP_REFERER', '')
            if not ret_json:
                return direct_to_template(request, 'server/login.html', 
                            {'ret': 'error<a href=' + next_url + '>back</a>', 
                             'data': query['data'], 
                             'url': getViewURL(request, endpoint), 
                             'next': next_url})
            else:
                response_data = {'prompt': 'openid login', \
                        'action': getViewURL(request, endpoint), \
                        'method': 'POST', \
                        'fields': [
                            {'type': 'text', 'name': 'user', 'label': 'Username: '},
                            {'type': 'password', 'name': 'passwd', 'label': 'Password: '},
                            {'type': 'hidden', 'name': 'data', 'value': query['data']},

                        ]
                }
                return http.HttpResponse(json.dumps(response_data), mimetype="application/json")
        login(request, user)
        query = pickle.loads(base64.decodestring(query['data']))

    s = getServer(request)

    # First, decode the incoming request into something the OpenID
    # library can use.
    try:
        openid_request = s.decodeRequest(query)
    except ProtocolError, why:
        # This means the incoming request was invalid.
        return direct_to_template(
            request,
            'server/endpoint.html',
            {'error': str(why)})

    # If we did not get a request, display text indicating that this
    # is an endpoint.
    if openid_request is None:
        return direct_to_template(
            request,
            'server/endpoint.html',
            {})

    # We got a request; if the mode is checkid_*, we will handle it by
    # getting feedback from the user or by checking the session.
    if openid_request.mode in ["checkid_immediate", "checkid_setup"]:
        return handleCheckIDRequest(request, openid_request)
    else:
        # We got some other kind of OpenID request, so we let the
        # server handle this.
        openid_response = s.handleRequest(openid_request)
        return displayResponse(request, openid_response)

def handleCheckIDRequest(request, openid_request):
    """
    Handle checkid_* requests.  Get input from the user to find out
    whether she trusts the RP involved.  Possibly, get intput about
    what Simple Registration information, if any, to send in the
    response.
    """
    # If the request was an IDP-driven identifier selection request
    # (i.e., the IDP URL was entered at the RP), then return the
    # default identity URL for this server. In a full-featured
    # provider, there could be interaction with the user to determine
    # what URL should be sent.
    for k in dir(openid_request):
        if k.startswith('_'):
            continue

    if not request.user.is_authenticated():
        ret_json = request.META.get('HTTP_ACCEPT', False) and \
            not (request.META['HTTP_ACCEPT'].find('html') > -1)

        query = util.normalDict(request.GET or request.POST)
        if not ret_json:
            return direct_to_template(request, 'server/login.html', 
                    {'ret': '', 'data': base64.encodestring(pickle.dumps(query)).strip('\n'), 
                    'url': getViewURL(request, endpoint), 'next': request.GET.get('next', '')})
        else:
            response_data = {'prompt': 'openid login', \
                             'action': getViewURL(request, endpoint), \
                             'method': 'POST', \
                             'fields': [
                                 {'type': 'text', 'name': 'user', 'label': 'Username: '},
                                 {'type': 'password', 'name': 'passwd', 'label': 'Password: '},
                                 {'type': 'hidden', 'name': 'data', 'value': base64.encodestring(pickle.dumps(query)).strip('\n')},

                             ]
            }
            return http.HttpResponse(json.dumps(response_data), mimetype="application/json")

    if not openid_request.idSelect():

        id_url = getViewURL(request, idPage, args=[request.user.username])
        # Confirm that this server can actually vouch for that
        # identifier
        if id_url != openid_request.identity:
            # Return an error response
            error_response = ProtocolError(
                openid_request.message,
                "This server cannot verify the URL %r" %
                (openid_request.identity,))

            return displayResponse(request, error_response)

    if openid_request.immediate:
        # Always respond with 'cancel' to immediate mode requests
        # because we don't track information about a logged-in user.
        # If we did, then the answer would depend on whether that user
        # had trusted the request's trust root and whether the user is
        # even logged in.
        openid_response = openid_request.answer(False)
        return displayResponse(request, openid_response)
    else:
        # Store the incoming request object in the session so we can
        # get to it later.

        setRequest(request, openid_request)
        return showDecidePage(request, openid_request)

@login_required
def showDecidePage(request, openid_request):
    """
    Render a page to the user so a trust decision can be made.

    @type openid_request: openid.server.server.CheckIDRequest
    """
    trust_root = openid_request.trust_root
    return_to = openid_request.return_to

    auth_site = AuthSites.objects.filter(uid = request.user.id, site = trust_root)
    if auth_site:
        if auth_site[0].permission == 1:
            request.POST = ['allow', ]
            return processTrustResult(request)
        else:
            request.POST = []
            return processTrustResult(request)
    try:
        # Stringify because template's ifequal can only compare to strings.
        trust_root_valid = verifyReturnTo(trust_root, return_to) \
                           and "Valid" or "Invalid"
    except DiscoveryFailure, err:
        trust_root_valid = "DISCOVERY_FAILED"
    except HTTPFetchingError, err:
        trust_root_valid = "Unreachable"

    pape_request = pape.Request.fromOpenIDRequest(openid_request)

    return direct_to_template(
        request,
        'server/trust.html',
        {'trust_root': trust_root,
         'trust_handler_url':getViewURL(request, processTrustResult),
         'trust_root_valid': trust_root_valid,
         'pape_request': pape_request,
         })

@login_required
def processTrustResult(request):
    """
    Handle the result of a trust decision and respond to the RP
    accordingly.
    """
    # Get the request from the session so we can construct the
    # appropriate response.
    openid_request = getRequest(request)

    # The identifier that this server can vouch for
    response_identity = getViewURL(request, idPage, args=[request.user.username])

    # If the decision was to allow the verification, respond
    # accordingly.
    allowed = 'allow' in request.POST or 'once' in request.POST

    # Generate a response with the appropriate answer.
    openid_response = openid_request.answer(allowed,
                                            identity=response_identity)
    # Send Simple Registration data in the response, if appropriate.
    if allowed:
        if ('allow' in request.POST) and \
            not AuthSites.objects.filter(
                uid = request.user.id,
                site = openid_request.trust_root):

            auth_site = AuthSites.objects.create(
                            uid = request.user.id,
                            site = openid_request.trust_root,
                            permission = 1)
            auth_site.save()

        sreg_data = {'username': request.user.username,
                     'mail': request.user.email,
                     'uid': str(request.user.id)}

        sreg_req = sreg.SRegRequest.fromOpenIDRequest(openid_request)
        sreg_resp = sreg.SRegResponse.extractResponse(sreg_req, sreg_data)
        openid_response.addExtension(sreg_resp)

        pape_response = pape.Response()
        pape_response.setAuthLevel(pape.LEVELS_NIST, 0)
        openid_response.addExtension(pape_response)

    return displayResponse(request, openid_response)

def displayResponse(request, openid_response):
    """
    Display an OpenID response.  Errors will be displayed directly to
    the user; successful responses and other protocol-level messages
    will be sent using the proper mechanism (i.e., direct response,
    redirection, etc.).
    """
    # ret_json = request.META.get('HTTP_ACCEPT', False) and \
    #         not (request.META['HTTP_ACCEPT'].find('html') > -1)
    # if ret_json:
    #     return http.HttpResponse(json.dumps({'status': 'ok'}), mimetype="application/json")

    s = getServer(request)

    # Encode the response into something that is renderable.
    try:
        webresponse = s.encodeResponse(openid_response)
    except EncodingError, why:
        # If it couldn't be encoded, display an error.
        text = why.response.encodeToKVForm()
        return direct_to_template(
            request,
            'server/endpoint.html',
            {'error': cgi.escape(text)})

    # Construct the appropriate django framework response.
    r = http.HttpResponse(webresponse.body)
    r.status_code = webresponse.code

    for header, value in webresponse.headers.iteritems():
        r[header] = value

    return r
