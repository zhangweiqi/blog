from flask import Blueprint

main=Blueprint('main',__name__)

from . import views, errors
from ..models import Permission


@main.app_context_processor
def inject_permissions():
    """
    Variable can be used in all templates.
    :return:
    """
    return dict(Permission=Permission)