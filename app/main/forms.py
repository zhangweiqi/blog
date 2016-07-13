# coding: utf-8
from flask_wtf import Form
from wtforms import TextAreaField, SubmitField, StringField, BooleanField, \
    SelectField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp
from ..models import Role, User
import sys
reload(sys)
sys.setdefaultencoding('utf-8')


class EditProfileForm(Form):
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('地址', validators=[Length(0, 64)])
    introduction = TextAreaField('个性签名')
    submit = SubmitField('提交')


class EditProfileAdminForm(Form):
    email = StringField('电子邮箱', validators=[Required(), Length(1, 64), Email()])
    username = StringField('用户名', validators=[Required(), Length(1, 64), Regexp(
        '^[A-Za-z][A-Za-z0-9_]*$', 0, '用户名必须由字母、数字和下划线组成。'
    )])
    confirmed = BooleanField('是否已验证')
    role = SelectField('角色', coerce=int)
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('地址', validators=[Length(0, 64)])
    introduction = TextAreaField('个性签名')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)  # ?
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user  # ?

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('该电子邮箱已注册！')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('该用户名已被使用！')


class PostForm(Form):
    post = TextAreaField("有什么新鲜事想告诉大家？", validators=[Required()])
    submit = SubmitField('提交')


class CommentForm(Form):
    body = StringField('评论', validators=[Required()])
    submit = SubmitField('提交')
