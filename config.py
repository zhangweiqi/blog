import os

basedir = os.path.abspath(os.path.dirname(__file__))


class config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secret of secret'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASK_ADMIN = os.environ.get('FLASK_ADMIN')
    FLASKY_POSTS_PER_PAGE = 10
    FLASKY_COMMENT_PER_PAGE = 10
    FLASKY_FOLLOWERS_PER_PAGE = 10
    FLASKY_FOLLOWEDS_PER_PAGE = 10
    FLASKY_COMMENTS_PER_PAGE_MODERATE = 20
    FLASKY_MAIL_SUBJECT_PREFIX = 'Blog_of_Zhang'
    FLASKY_MAIL_SENDER = 'zhangweiqi1015@gmail.com'

    # administrator's emails, when these email are registering,
    # they will be given admin role.

    @staticmethod
    def init_app(app):
        pass


class developconfig(config):
    DEBUG = True
    SQL_DATABASE_URL = os.environ.get('DEV_DATABASE_URL') or \
                       'mysql://username:password@hostname/' \
                       + os.environ.get(basedir, 'data-dev.sql')


class testconfig(config):
    TESTING = True
    SQL_DATABASE_URL = os.environ.get('TEST_DATABASE_URL') or \
                       'mysql://username:password@hostname/' \
                       + os.environ.get(basedir, 'data-test.sql')


class productconfig(config):
    SQL_DATABASE_URL = os.environ.get('PRO_DATABASE_URL') or \
                       'mysql://username:password@hostname/' \
                       + os.environ.get(basedir, 'data-pro.sql')


config = {
    'develop': developconfig,
    'test': testconfig,
    'product': productconfig,
    'default': developconfig
}
