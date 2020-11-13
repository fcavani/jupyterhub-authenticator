import os
import json
from base64 import b64decode
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from traitlets import Unicode, Callable
import jwt


DEFAULT_COOKIE_NAME = "XSRF-TOKEN"


class JSONWebTokenLoginHandler(BaseHandler):

    async def get(self):
        # Read config
        cookie_name = self.authenticator.cookie_name
        rsa_public_key = self.authenticator.rsa_public_key
        signing_certificate = self.authenticator.signing_certificate
        secret = self.authenticator.secret
        username_claim_field = self.authenticator.username_claim_field
        audience = self.authenticator.expected_audience

        # Read values
        auth_cookie_content = self.get_cookie(cookie_name, "")

        # Determine whether to use cookie content or query parameters
        decoded = dict()
        if auth_cookie_content:
            try:
                decoded = self.verify_jwt(
                    auth_cookie_content,
                    secret=secret,
                    signing_certificate=signing_certificate,
                    rsa_public_key=rsa_public_key,
                    audience=audience
                )
                self.log.info("Successfully decoded access and refresh tokens")
            except ExceptionJWT:
                if self.redirect_to_sso():
                    return
        else:
            if self.redirect_to_sso():
                return

        # JWT was valid
        username = self.retrieve_username(decoded, username_claim_field)

        if self.authenticator.validate_token_hook:
            valid = self.authenticator.validate_token_hook(auth_cookie_content)
            if not valid:
                if self.redirect_to_sso():
                    return

        user = self.user_from_username(username)
        self.set_login_cookie(user)

        home_dir = self.authenticator.home_dir
        if not home_dir:
            raise ExceptionMissingConfigurationParameter("Missing home directory.")
        user_path = os.path.join(
            home_dir,
            username
        )
        sso_path = os.path.join(
            str(user_path),
            self.authenticator.token_file
        )
        if not os.path.exists(user_path):
            os.makedirs(user_path)
        if os.path.exists(sso_path):
            os.remove(sso_path)
        with open(sso_path, "w+") as f:
            json.dump({
                'jwt': auth_cookie_content
            }, f, indent=2)

        # Redirect to the next url until the user arrives at the Jupyter environment.
        _url = url_path_join(self.hub.server.base_url, 'spawn')
        next_url = self.get_argument('next', default=False)
        if next_url:
             _url = next_url
        self.redirect(_url)

    def redirect_to_sso(self):
        hook = self.authenticator.redirect_to_sso_hook
        if not hook:
            return False
        self.redirect(hook(self))
        return True

    def verify_jwt(self,
                   token, 
                   secret = None,
                   signing_certificate = None,
                   rsa_public_key = None,
                   audience = None):
        claims = ""
        if secret:
            claims = self.verify_jwt_using_secret(token, secret, audience)
        elif signing_certificate:
            claims = self.verify_jwt_using_certificate(token, signing_certificate, audience)
        elif rsa_public_key:
            claims = self.verify_jwt_using_secret(token, b64decode(rsa_public_key.encode()).decode(), audience)
        else:
            raise ExceptionJWT("JWT not valid")
        return claims

    def verify_jwt_using_certificate(self, token, signing_certificate, audience):
        with open(signing_certificate, 'r') as rsa_public_key_file:
            secret = rsa_public_key_file.read()
            return self.verify_jwt_using_secret(token, secret, audience)

    def verify_jwt_using_secret(self, token, secret, audience):
        # If no audience is supplied then assume we're not verifying the audience field.
        if audience == "":
            audience = None
        try:
            return jwt.decode(token, secret, algorithms=['RS256'], audience=audience)
        except jwt.ExpiredSignatureError:
            self.log.error("Token has expired")
            raise ExceptionJWT("Token has expired")
        except jwt.PyJWTError as ex:
            self.log.error("Token error - %s", ex)
            raise ExceptionJWT("Token error")
        except Exception as ex:
            self.log.error("Could not decode token claims - %s", ex)
            raise ExceptionJWT("Could not decode token claims")

    @staticmethod
    def retrieve_username(claims, username_claim_field):
        # retrieve the username from the claims
        username = claims[username_claim_field]
        # Our system returns the username as an integer - convert to string
        if not isinstance(username, str):
            username = "%s" % username
        if "@" in username:
            # process username as if email, pull out string before '@' symbol
            return username.split("@")[0]
        else:
            # assume not username and return the user
            return username


class JSONWebTokenAuthenticator(Authenticator):
    """
    Accept the authenticated JSON Web Token from header or query parameter.
    """
    redirect_unauthorized = Unicode(
        default_value='',
        config=True,
        help="""Login url to redirect if can't login."""
    )

    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    rsa_public_key = Unicode(
        config=True,
        help="""
        String with rsa public key encoded with base64.
        """
    )

    cookie_name = Unicode(
        config=True,
        default_value=DEFAULT_COOKIE_NAME,
        help="""The name of the cookie where is stored the JWT token""")

    username_claim_field = Unicode(
        default_value='upn',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    secret = Unicode(
        config=True,
        help="""Shared secret key for signing JWT token.  If defined, it overrides any setting for signing_certificate""")

    home_dir = Unicode(
        config=True,
        help="""Home directory.""")
    
    token_file = Unicode(
        default_value='.jwt_sso.json',
        config=True,
        help="""User token file name.""")
        
    validate_token_hook = Callable(
        default_value=None,
        allow_none=True,
        config=True,
        help="""Function that will be called when the validation of the token are required."""
    )

    redirect_to_sso_hook = Callable(
        default_value=None,
        allow_none=True,
        config=True,
        help="""Function that will be called when the jwt is invalid. This redirect to sso login url. """
    )

    def get_handlers(_self, _app):
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    async def authenticate(_self, _handler, _data):
        raise NotImplementedError()

    async def pre_spawn_start(self, user, spawner):
        if not self.home_dir:
            raise ExceptionMissingConfigurationParameter("Missing home directory.")
        path = os.path.join(
            self.home_dir,
            user.name,
            self.token_file
        )
        try:
            with open(path, "r") as f:
                jwt = json.load(f)
        except Exception as ex:
            self.log.error("Can't load token from file!", ex)
            spawner.environment['JWT'] = ''
            return
        spawner.environment['JWT'] = jwt['jwt']

    async def refresh_user(self, user, handler, force=False):
        self.log.info(f"refresh user {user.name}, force={force}, home dir: {self.home_dir}")
        if force:
            return False
        if self.home_dir:
            path = os.path.join(
                self.home_dir,
                user.name,
                self.token_file
            )
            valid = await self._validate_auth_token(user, path)
            if valid:
                return True
        self.log.info(f"quicking off user {user.name} (force={force}, home_dir={self.home_dir})")
        await self._quick_off_user(handler)
        return False

    async def _validate_auth_token(self, user, path):
        try:
            with open(path, "r") as f:
                jwt = json.load(f)
            token = jwt['jwt']
            if token and self.validate_token_hook:
                if self.validate_token_hook(token):
                    self.log.info(f"user {user.name} have a valid token")
                    return True
        except Exception as ex:
            self.log.error(f"Can't load token from file for user {user.name}: {ex}")
        self.log.info(f"user {user.name} have a invalid token")
        return False

    async def _quick_off_user(self, handler):
        handler.clear_cookie(self.cookie_name)
        handler.clear_cookie("jupyterhub-hub-login")
        handler.clear_cookie("jupyterhub-session-id")


class JSONWebTokenLocalAuthenticator(JSONWebTokenAuthenticator, LocalAuthenticator):
    """
    A version of JSONWebTokenAuthenticator that mixes in local system user creation
    """
    pass


class ExceptionJWT(Exception):
    pass


class ExceptionMissingConfigurationParameter(Exception):
    pass
