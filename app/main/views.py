from . import main
from .forms import PostForm
from flask import current_app
from flask_login import current_user
from ..models import Permission



@main.route('/',methods=['GET','POST'])
def index():
    form=PostForm()
    if current_user.can(Permission.WRITE_ARTICLES):
