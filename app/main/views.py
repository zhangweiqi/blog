from . import main
from .forms import PostForm
from flask import current_app, abort
from flask_login import current_user
from ..models import Permission


@main.after_app_request()
def after_request():


@main.route('/shutdown')
def server_shutdown():


@main.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES):









