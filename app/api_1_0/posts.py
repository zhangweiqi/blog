from flask import jsonify,request,g,abort,url_for,current_app
from .. import db
from ..models import Post,Permission
from . import api
from .decorators import permission_required
from .errors import forbidden

@api.route('/posts/')
def 