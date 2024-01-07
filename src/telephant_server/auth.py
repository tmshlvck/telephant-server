import telephant_server
import telephant_server.db

# the google part is based on https://medium.com/@vivekpemawat/enabling-googleauth-for-fast-api-1c39415075ea
# and https://github.com/hanchon-live/tutorial-fastapi-oauth/blob/master/apps/jwt.py
# and https://docs.authlib.org/en/v0.15.3/client/fastapi.html

import os
from datetime import datetime

from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client import OAuthError
from fastapi import Request
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse,HTMLResponse
from typing import Dict, Annotated
from fastapi import status, Form
from fastapi.exceptions import HTTPException

import random
import string


def create_auth(auth_app, root_endpoint):
    @auth_app.post('/web/v1/login/password')
    async def login_password(request: Request, email: Annotated[str, Form()], password: Annotated[str, Form()]):
        dbuser = telephant_server.db.login_user_password(email, password)
        if dbuser:
            request.session['user'] = {'email': dbuser.email, 'fullname': dbuser.fullname}        
            return await root_endpoint(request)
        else:
            return await root_endpoint(request, showmessage="Login failed!")
        
    # Set up OAuth
    config_data = {'GOOGLE_CLIENT_ID': telephant_server.config.get('auth', {}).get('google', {}).get('client_id'),
                   'GOOGLE_CLIENT_SECRET': telephant_server.config.get('auth', {}).get('google', {}).get('client_secret')}
    starlette_config = Config(environ=config_data)
    oauth = OAuth(starlette_config)
    oauth.register(
        name='google',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )
    
    # Set up the middleware to read the request session
    auth_app.add_middleware(SessionMiddleware, secret_key=telephant_server.config['session_secret'])

    @auth_app.get('/web/v1/login/google')
    async def login_google(request: Request):
        google_redirect_uri = f"{telephant_server.config.get('url_base', 'http://localhost/').rstrip('/')}/web/v1/token/google"
        return await oauth.google.authorize_redirect(request, google_redirect_uri)   
    
    @auth_app.get('/web/v1/token/google')
    async def auth_google(request: Request):
        try:
            token = await oauth.google.authorize_access_token(request)
        except OAuthError as e:
            return HTMLResponse(f'OAuthError: <pre>{e.error}<pre>')
        user = token.get('userinfo')
        if user:
            dbuser = telephant_server.db.login_user_google(user)
            if dbuser:
                request.session['user'] = {'email': dbuser.email, 'fullname': dbuser.fullname}
        
        return RedirectResponse(url='/')

    @auth_app.get('/web/v1/logout')
    async def logout(request: Request):
        request.session.pop('user', None)
        return RedirectResponse(url='/')

def get_user_cookie(request: Request) -> Dict[str, str]:
    """
    returns: {'email': str(email), 'fullname': str(fullname)}
    """
    return request.session.get('user', None)

def get_user_email(request: Request) -> str:
    uc = get_user_cookie(request)
    if uc:
        return uc.get('email')
    else:
        return None
    
def require_user_email(request: Request) -> str:
    usereml = get_user_email(request)
    if not usereml:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing user token",
        )
    return usereml

def require_admin_email(request: Request) -> str:
    usereml = require_user_email(request)
    if usereml in telephant_server.config.get('admins', {}):
        return usereml
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing user token",
        )

def gen_api_key(keylen=32):
    # get random string of letters and digits
    source = string.ascii_letters + string.digits
    return ''.join((random.choice(source) for i in range(keylen)))
