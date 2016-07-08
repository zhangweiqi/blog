# coding: utf-8
import os


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secret of secret'
    SSL_DISABLE = True  # Use SSL or not(only used in production).
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_RECORD_QUERIES = True  # Tell Flask-SQLAlchemy open 'order-query-statistics-number'
    # for logging SQLAlchemy slow query
    MAIL_SERVER = 'smtp.cntv.cn'
    MAIL_PORT = 25
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    SLOW_DB_QUERY_TIME = 0.5
    ADMIN_EMAIL = os.environ.get('FLASK_ADMIN')  # Store the e-mai addresses of administers
    POSTS_PER_PAGE = 10
    COMMENTS_PER_PAGE = 20
    FOLLOWERS_PER_PAGE = 30
    FOLLOWEDS_PER_PAGE = 30
    COMMENTS_PER_PAGE_MODERATE = 20
    MAIL_SUBJECT_PREFIX = '迷幻'
    MAIL_SENDER = 'zhangwq1015@outlook.com'

    @staticmethod
    def init_app(app):
        pass


class DevelopConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URL = os.environ.get('DEV_DATABASE_URL') or \
                              'mysql://root:zwq6631666!@localhost/dev'


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URL = os.environ.get('TEST_DATABASE_URL') or \
                              'mysql://root:zwq6631666!@localhost/test'
    WTF_CSRF_ENABLED = False  # avoid handle CSRF token


class ProductConfig(Config):
    SQLALCHEMY_DATABASE_URL = os.environ.get('PRO_DATABASE_URL') or \
                              'mysql://root:zwq6631666!@localhost/pro'
    SSL_DISABLE = False

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # email errors to the administrators
        import logging
        from logging.handlers import SMTPHandler
        credentials = None
        secure = None
        if getattr(cls, 'MAIL_USERNAME', None) is not None:
            credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
            if getattr(cls, 'MAIL_USE_TLS', None):
                secure = ()
        mail_handler = SMTPHandler(
            mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
            fromaddr=cls.MAIL_SENDER,
            toaddrs=[cls.ADMIN_EMAIL],
            subject=cls.MAIL_SUBJECT_PREFIX + ' Application Error',
            credentials=credentials,
            secure=secure)
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)



config = {
    'develop': DevelopConfig,
    'test': TestConfig,
    'product': ProductConfig,
    'default': DevelopConfig
}
