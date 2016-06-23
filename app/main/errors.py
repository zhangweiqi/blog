from flask import render_template, request, jsonify
from . import main


@main.app_errorhandler(403)  # this decorator for all error page
def forbidden(e):
    if request.accept_mimetypes.accept_json and \
            not request.accept_mimetypes.accept_html:  # when request accept_mimetype
        response = jsonify({'error': 'Forbidden'})  # is json
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
