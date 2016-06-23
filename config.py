import os

basedir = os.path.abspath(os.path.dirname(__file__))


class config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secret of secret'
    SQLALCHEMY_COMMIT_ON_TEARDOWN=True
    FLASK_ADMIN=os.environ.get('FLASK_ADMIN')
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
