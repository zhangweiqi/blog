# coding:utf-8
from config import config
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()
bootstrap = Bootstrap()
mail=Mail()
login_manager=LoginManager()
login_manager.session_protection='strong'
login_manager.login_view='auth.login'   # 'auth.login' is login_page blueprint route
login_manager.login_message='请先登陆！' # flash message

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    db.init_app(app)
    bootstrap.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    return app
