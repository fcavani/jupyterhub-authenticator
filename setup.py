try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


import os.path

readme = ''
here = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(here, 'README.md')
if os.path.exists(readme_path):
    with open(readme_path, 'rb') as stream:
        readme = stream.read().decode('utf8')


setup(
    long_description=readme,
    name='jupyterhub-authenticator',
    version='1.0.0',
    description='Rentbrella JupyterHub JWT Authenticator',
    python_requires='>=3.6.4',
    author='Rentbrella',
    author_email='ti@rentbrella.com',
    packages=['jwtauthenticator'],
    package_dir={"": "."},
    package_data={},
    install_requires=['jupyterhub>=1.0.0', 'pyjwt>=1.7.1'],
)
