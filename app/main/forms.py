# coding: utf-8
from flask_wtf import Form
from wtforms import TextAreaField, SubmitField
from wtforms.validators import Required

class PostForm(Form):
    body=TextAreaField("记录你的生活", validators=[Required()])
    submit= SubmitField('提交')

