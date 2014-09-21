import functools
import logging
import urllib

from tornado import auth, escape, httpclient, httputil

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class OpenHumansMixin(auth.OAuth2Mixin):
    """
    OpenHumans OAuth Mixin, based on FacebookGraphMixin
    """

    _OAUTH_AUTHORIZE_URL = 'https://openhumans.org/oauth2/authorize'
    _OAUTH_ACCESS_TOKEN_URL = 'https://openhumans.org/oauth2/access_token'

    _API_URL = 'https://openhumans.org/api'

    @auth._auth_return_future
    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
                               code, callback):
        """
        Handles the login for OpenHumans, queries /user and returns a user
        object
        """
        http = httpclient.AsyncHTTPClient()

        body = urllib.urlencode({
            'redirect_uri': redirect_uri,
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'authorization_code',
        })

        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   functools.partial(self._on_access_token_cb, callback),
                   method="POST",
                   headers={
                       'Content-Type': 'application/x-www-form-urlencoded'
                   },
                   body=body)

    @staticmethod
    def _on_access_token_cb(future, response):
        """
        callback for authentication url, if successful get the user details
        """
        if response.error:
            logger.warning('OpenHumans auth error: %s', str(response))

            future.set_result(None)

            return

        logger.debug('response body: %s', response.body)

        args = escape.json_decode(response.body)

        if 'error' in args:
            logger.error('oauth error ' + args['error'])

            future.set_exception(Exception(args['error']))

            return

        future.set_result(args)

    def open_humans_request(self, path, callback, access_token=None,
                            method='GET', body=None, **args):
        """
        Makes an Open Humans API request, rerturns the parsed data
        """
        args['access_token'] = access_token
        args['format'] = 'json'

        url = httputil.url_concat(self._API_URL + path, args)

        logger.debug('request to ' + url)

        http = httpclient.AsyncHTTPClient()

        if body is not None:
            body = escape.json_encode(body)

            logger.debug('body is' + body)

        http.fetch(url,
                   callback=functools.partial(self._parse_response, callback),
                   method=method,
                   body=body)

    @staticmethod
    def _parse_response(callback, response):
        """
        Parse the JSON from the API
        """
        if response.error:
            logger.warning('HTTP error from OpenHumans: %s', response.error)

            callback(None)

            return

        try:
            json_body = escape.json_decode(response.body)
        except TypeError:
            logger.warning('Invalid JSON from OpenHumans: %r', response.body)

            json_body = {}

        if json_body.get('error_code'):
            logger.warning('Open Humans error: %d: %r',
                           json_body['error_code'],
                           json_body.get('error_msg'))

            callback(None)

            return

        callback(json_body)
