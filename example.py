import logging
import os

from tornado import escape, httpserver, ioloop, options, web

from .open_humans import OpenHumansMixin

options.define('port', default=8001, help='run on the given port', type=int)

options.define('open_humans_key', help='your Open Humans application key',
               type=str)
options.define('open_humans_secret', help='your Open Humans application secret',
               type=str)


class OpenHumansLoginHandler(web.RequestHandler, OpenHumansMixin):
    _OAUTH_REDIRECT_URL = 'http://localhost:8001/auth/open-humans'

    # Overridden for local development
    _OAUTH_AUTHORIZE_URL = 'http://localhost:8000/oauth2/authorize'
    _OAUTH_ACCESS_TOKEN_URL = 'http://localhost:8000/oauth2/access_token'

    @web.asynchronous
    def get(self):
        redirect_uri = self._OAUTH_REDIRECT_URL

        # if we have a code, we have been authorized so we can log in
        if self.get_argument('code', False):
            self.get_authenticated_user(
                redirect_uri=redirect_uri,
                client_id=self.settings['open_humans_key'],
                client_secret=self.settings['open_humans_secret'],
                code=self.get_argument('code'),
                callback=self._on_login)

            return

        # otherwise we need to request an authorization code
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.settings['open_humans_key'],
            extra_params={'scope': 'read+write'})

    def _on_login(self, user):
        """
        This handles the user object from the login request
        """
        if user:
            logging.info('logged in user from openhumans: ' + str(user))

            self.set_secure_cookie('user', escape.json_encode(user))
        else:
            self.clear_cookie('user')

        self.redirect('/')


class BaseHandler(web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie('user')

        if not user_json:
            return None

        return escape.json_decode(user_json)


class AuthLogoutHandler(BaseHandler, OpenHumansMixin):
    def get(self):
        self.clear_cookie('user')
        self.redirect(self.get_argument('next', '/'))


class MainHandler(BaseHandler, OpenHumansMixin):
    # Overridden for local development
    _API_URL = 'http://localhost:8000/api'

    @web.authenticated
    @web.asynchronous
    def get(self):
        self.open_humans_request('/american-gut/user-data/current/',
                                 self._on_user_data,
                                 access_token=self.current_user['access_token'])

    def _on_user_data(self, user_data):
        if user_data is None:
            # Session may have expired
            self.redirect('/auth/open-humans')

            return

        self.render('user-data.html', user_data=user_data)


class Application(web.Application):
    def __init__(self):
        handlers = [
            (r'/', MainHandler),
            (r'/auth/open-humans', OpenHumansLoginHandler),
            (r'/auth/logout', AuthLogoutHandler),
        ]

        settings = dict(
            cookie_secret='__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__',
            login_url='/auth/open-humans',
            template_path=os.path.join(os.path.dirname(__file__), 'templates'),
            static_path=os.path.join(os.path.dirname(__file__), 'static'),
            xsrf_cookies=True,
            open_humans_key=options.options.open_humans_key,
            open_humans_secret=options.options.open_humans_secret,
            debug=True,
            autoescape=None)

        web.Application.__init__(self, handlers, **settings)


def main():
    options.parse_command_line()

    if not (options.options.open_humans_key and
            options.options.open_humans_secret):
        print '--open_humans_key and --open_humans_secret must be set'

        return

    http_server = httpserver.HTTPServer(Application())
    http_server.listen(options.options.port)

    ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
