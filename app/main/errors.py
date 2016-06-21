# -*- coding: utf-8 -*-
from flask import render_template, request, jsonify
from . import main


@main.app_errorhandler(403)  # 该函数作用于所有的错误页面
def forbidden(e):
    if request.accept_mimetypes.accept_json and \
            not request.accept_mimetypes.accept_html:  # 当请求报文的主体时json格式时
        response = jsonify({'error': 'Forbidden'})
        response.status_code = 403
        return response
    return render_template('403.html'), 403


@main.app_errorhandler(404)
def page_not_found(e):
    if request.accept_mimetypes.accept_json and \
            not request.accept_mimetypes.accept_html:
        response = jsonify({'error': 'Not Found'})
        response.status_code = 404
        return response
    return render_template('404.html'), 404


@main.app_errorhandler(500)
def Internal_server_error(e):
    if request.accept_mimetypes.accept_json and \
            not request.accept_mimetypes.accept_html:
        response = jsonify({'error': 'Internal Server Error'})
        response.status_code = 500
    return render_template('500.html'), 500
