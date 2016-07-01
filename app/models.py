# coding: utf-8
from . import db, login_manager
from datetime import datetime
import hashlib
from flask import request, current_app, url_for
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import bleach
from markdown import markdown
from exceptions import ValidationError

class Permission(object):
    """
    (0x:hexadecimal)The max num is 128,as binary system have eight digits,
    every digit delegate a authority with boolean,
    so it hava as far as eight authorities.Combining eight boolean nums and
    transform it to hexadecimal,users can get their authorities.
    """
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

    def __repr__(self):  # representation
        return '<Role %r>' % self.name


class User(UserMixin, db.Models):  # inherit from SQLAlchemy and flask-login
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    # 'role.id' shows this columns value is the 'id' value in model 'Role'(model's name si roles)
    password = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(128))
    introduction = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))  # gravatar  head portrait code
    followed = db.relationship('Follow', foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic', cascade='all,delete-orphan')  # all Follow user as follower
    follower = db.relationship('Follow', foreign_key=[Follow.followed_id],
                               backref=db.backref('followed', lazy='joined'),
                               lazy='dynamic', cascade='all,delete-orphan')  # all Follow user as followed
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    @staticmethod
    def generate_fake(count=100):
        """generate fake user."""
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()  # Changing the seed of the random number generator, can be used
        for i in range(count):  # before import other random function modules.
            u = User(email=forgery_py.internet.email_address(),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     introduction=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.data(True))
            db.session.add(u)

            # Users'es username and email is unique,but forgery_py may generate
            # repetitive things.If it generates repetitive things, IntegrityError will happen when
            # commit.
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    @staticmethod
    def add_self_follows():
        """
        Make every user follow themselves by circulation.
        :return:
        """
        for user in User.query.all():  # return all results in form of list.
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    @property  # descriptor: Define the password's attribute.
    def password(self):
        """define password's property is AttributeError."""
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        """generate password_hash by password."""
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """check the password with the passowrd_hash."""
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        """
        use SECRET_KEY and 'key-value's  to generate a token(confirm account).
        :param expiration: period of validity, unit is second.
        :return:a token :to confirm the user_id.
        """
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})  # generate a token string.

    def confirm(self, token):
        """
        use SECRET_KEY and token to confirm the user_id(confirm account).
        :param token:
        :return: if token is user's,return true;else return false.
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)  # decode token, if wrong, generate error.data is a dictionary.
        except():
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        """
        use SECRET_KEY and 'key-value' to generate a token(reset password).
        :param expiration: period of validity, unit is second.
        :return:a token :to confirm the reset password.
        """
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        """
        use token and SECRET_KEY to confirm the user_id.
        :param token:
        :param new_password:
        :return: boolean : success-true; fail-false
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except():
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        return True

    def generate_email_change_token(self, new_email, expiration):
        """

        :param new_email:
        :param expiration:
        :return: token
        """
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        """
        confirm the user_id and new_email.
        :param token:
        :return: boolean
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except():
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        self.email = new_email
        self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True

    def ping(self):
        """
        refresh the last_seen.
        :return: nothing
        """
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def gravatar(self, size=100, default='identicon', rating='g'):  # get head portrait
        """structure head portrait URL
        size:100px;
        default:Users without register Gravatar use default pictures-produce way,
        picture builder: identicon;
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
        Firstly call base class's function, if still not define role after
        create base class object, then define the role is admin or default
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

    def follow(self, user):  # follow user
        """
        current_user follow user.
        :param user: followed
        :return:
        """
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):  # cancel follow user
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        """
        if current_user has followed user, return True; if not followed ,return False.
        """
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        """
        if current_user has been followed, return True; if not been followed,return False.
        """
        return self.follower.filter_by(follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        """
        Post: return a object of Post;
        Follow.follower_id==self.id : query from the model of Follow ;
        join: join the Follow and Post.
        :return: a joined excel.
        """
        return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
            .filter(Follow.follower_id == self.id)

    def to_json(self):  # ?
        json_user = {
            'url': url_for('api.get_post', id=self.id, _external=True),
            'username':self.username,
            'member_since':self.member_since,
            'last_seen':self.last_seen,
            'posts':url_for('api.get_user_posts',id=self.id,_external=True),
            'followed_posts':url_for('api.get_user_followed_posts',id=self.id,_external=True),
            'post_count':self.posts.count()
        }
        return json_user

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id}).decode('ascii')  # token

    @staticmethod
    def verify_auth_token(token):
        """Get current_user_id by token."""
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except():
            return None
        return User.query.get(data['id'])

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    """
    When user do not login, current_user is AnonymousUser.
    """

    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser  # ?


@login_manager.user_loader()
def load_user(user_id):
    """Get the user with user_id."""
    return User.query.get(int(user_id))  # return the row that specified primary key correspond


class Follow(db.Model):
    """
    The association table of Role and User.
    """
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()  # return the number of the query result.
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()  # offset: offset the result of
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),  # the original query,return a new query.
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        """
        Transform markdown to html.
        :param target:
        :param value:
        :param oldvalue:
        :param initiator:
        :return:
        """
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkifty(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

    def to_json(self):
        json_post={
            'url':url_for('api.get_post',id=self.id, _external=True),# _external=True means return whole URL.
            'body': self.body,
            'body_html':self.body_html,
            'timestamp':self.timestamp,
            'author':url_for('api.get_user',id=self.author_id,_external=True),
            'comments':url_for('api.get_comments',id=self.id,_external=True),
            'comment_count':self.comments.count()
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        body=json_post.get('body')
        if body is None or body == '':
            raise ValidationError('文章无内容！')
        return Post(body=body)




db.event.listen(Post.body, 'set', Post.on_changed_body())
"""
The function 'on_changed_body' is registered in 'Post.body',its the listener of
the event 'set' of SQLAlchemy. So if the body of instance changed, function will be import.
"""


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)  # admin use it to ban improper comments
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
                        'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

    def to_json(self):
        json_comment={
            'url':url_for('api.get_comment',id=self.id,_external=True),
            'post':url_for('api.get_post',id=self.id,_external=True),
            'body':self.body,
            'body_html':self.body_html,
            'timestamp':self.timestamp,
            'author':url_for('api.get_user',id=self.author_id,_external=True),
        }
        return json_comment

    @staticmethod
    def from_json(json_comment):
        body=json_comment.get('body')
        if body is None or body == '':
            raise ValidationError('评论无内容！')
        return Comment(body=body)

db.event.listen(Comment.body,'set',Comment.on_changed_body())
