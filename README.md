# JupyterHub Authenticator

Authenticate to JupyterHub using the JSONWebToken.

Originally forked from [https://github.com/qctrl/jwtauthenticator](qctrl/jupyterhub-authenticator) with the following modifications thus far:

- Make it more generic: add some hooks to customize the sso handling redirection to sso login page
  and a call to a sso validation endpoint.
- Cache the jwt token.

For more information about how to install and others procedures please check the 
[https://github.com/qctrl/jwtauthenticator](qctrl) page at github.

## License

See [LICENSE](LICENSE).
