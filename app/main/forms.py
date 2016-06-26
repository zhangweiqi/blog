# coding: utf-8
from flask_wtf import Form
from wtforms import TextAreaField, SubmitField, StringField
from wtforms.validators import Required, Length, Email,Regexp


class EditProfileForm(Form):
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('地址', validators=[Length(0, 64)])
    introduction = TextAreaField('个性签名')
    submit = SubmitField('提交')


class EditProfileAdminForm(Form):
    email = StringField('电子邮箱', validators=[Required(), Length(1, 64), Email()])
    username=StringField('用户名',validators=[Required(),Length(1,64),Regexp(
        '^[A-Za-z][A-Za-z0-9_.]*$', 0,'用户名必须由 '
    )])

class PostForm(Form):
    body = TextAreaField("记录你的生活", validators=[Required()])
    submit = SubmitField('提交')
