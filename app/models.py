from . import db
from datetime import datetime
import hashlib
from flask import request, current_app
from flask_login import UserMixin, AnonymousUserMixin


class Permission(object):
    """(0x:hexadecimal)The max num is 128,as binary system have eight digits,
    every digit delegate a authority with boolean,
    so it hava as far as eight authorities.Combining eight boolean nums and
    transform it to hexadecimal,users can get their authorities. """
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)  # ?
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    # for the instance of Role, 'users' return the list of users who relate to the role,
    # 'backref' add a attribute to User, that defines negative relationship.
    # this attribute can visit Role take the place of 'role_id',
    # it get the object of model,not the value of foreignkey.

    # lazy=dynamic: appoint the way of loading the record,this means not load,
    # but offer the query of loading.


    @staticmethod
    def insert_roles():  # do not understand
        roles = {
            'User': (
                Permission.FOLLOW |
                Permission.COMMENT |
                Permission.WRITE_ARTICLES, True),  # () Tuple   | or
            'Moderator': (  # someone who presides over a forum or debate
                Permission.FOLLOW |
                Permission.COMMENT |
                Permission.MODERATE_COMMENTS |
                Permission.WRITE_ARTICLES, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = role[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()


class User(UserMixin, db.Models):  # inherit from SQLAlchemy and flask-login
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role = db.Column(db.Integer, db.ForeignKey('roles.id'))
    # 'role.id' shows this columns value is the 'id' value in model 'Role'(model's name si roles)
    password = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(128))
    introduction = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))  # gravatar  head portrait code

    def gravatar(self, size=100, default='identicon', rating='g'):  # get head portrait
        """structure head portrait URL
        size:100px;
        default:Users without register Gravatar use default pictures-produce way,
        picture builder:identicon;
        rating:picture level."""
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        # encode:code with type of utf-8    hexdigest():hexadecimal
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def __init__(self, **kwargs):
        """
        Define the role of users.
        Firstly call baseclass's function, if still not define role after
        create baseclass object, then define the role is admin or default
        depend on email address.
        :param kwargs:
        """
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()
        self.followed.append(Follow(follow=self))

    def can(self, permissions):
        """
        Verify the permissions of user is or not param.
        :param permissions:
        :return:boolean
        """
        return self.role is not None and \
               (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        """
        Verify the user is or not administer.
        :return: boolean
        """
        return self.can(Permission.ADMINISTER)


class AnonymousUser(AnonymousUserMixin):
    """
    When user do not login, current_user is AnonmousUser.
    """
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False
