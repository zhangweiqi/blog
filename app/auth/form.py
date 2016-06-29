# coding: utf-8
from flask_wtf import Form
from wtforms import StringField, BooleanField, SubmitField, PasswordField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from ..models import User


class LoginForm(Form):
    email = StringField('电子邮箱', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('密码', validators=[Required()])
    remeber_me = BooleanField('记得我')
    submit = SubmitField('登录')


class RegistrationForm(Form):
    email = StringField('电子邮箱', validators=[Required, Length(1, 64), Email()])
    username = StringField('用户名', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_]*$', 0,
                                          '用户名必须为字母、数字和下划线！')])
    password = PasswordField('密码', validators=[
        Required(), EqualTo('password2', message='密码必须一致！')])
    password2 = PasswordField('确认密码', validators=[Required()])
    submit = SubmitField('注册')

    def validate_email(self, field):
        """
        Validate the email is registered or not.
        :param field: email
        :return:
        """
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该电子邮箱已被注册！')

    def validate_username(self, field):
        """
        Validate the username is registered or not.
        :param field: username
        :return:
        """
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('该用户名已被注册！')


class ChangePasswordForm(Form):
    old_password = PasswordField('旧密码', validators=[Required()])
    password = PasswordField('新密码', validators=[
        Required(), EqualTo('password2', message='密码必须相同！')])
    password2 = PasswordField('确认密码', validators=[Required()])
    submit = SubmitField('更新密码')


class Password_Reset_Request_Form(Form):
    email = StringField('电子邮箱', validators=[Required(), Length(1, 64),
                                            Email()])
    submit = SubmitField('重设密码')


class Password_Reset_Form(Form):
    email = StringField('电子邮箱', validators=[Required(), Length(1, 64),
                                            Email()])
    password = PasswordField('新密码', validators=[
        Required(), EqualTo('Password2', message='密码必须相同！')])
    password2 = PasswordField('确认密码', validators=[Required()])
    submit = SubmitField('重设密码')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Unknown email address.')


class Change_Email_Form(Form):
    email = StringField('新邮箱', validators=[Required(), Length(1, 64),
                                           Email()])
    password = PasswordField('密码', validators=[Required()])
    submit = SubmitField('更新电子邮件')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该电子邮箱已被注册！')
