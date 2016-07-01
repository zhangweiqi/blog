# coding: utf-8
from flask import g, jsonify
from flask_httpauth import HTTPBasicAuth
from ..models import User, AnonymousUser
from . import api
from .errors import unauthorized, forbidden

authentication = HTTPBasicAuth()


@authentication.verify_password
def verify_password(email, password):
    if email == '':
        g.current_user = AnonymousUser()
        return True
    user = User.query.filter_by(email=email).first()
    if not user:
        return False
    g.current_user = user
    return user.verify_password(password)


@authentication.error_handler()
def auth_error():
    return unauthorized('无效证书！')


@api.before_request()
@authentication.login_required()
def before_request():
    if not g.current_user.is_anonymous and \
            not g.current_user.confirmed:
        return forbidden('账户未认证！')


@api.route('/token')
def get_token():
    if g.current_user.is_anonymous or g.token_used:
        return unauthorized('无效认证！')
    return jsonify({'token': g.current_user.generate_auth_token(
        expiration=3600), 'expiration': 3600})
