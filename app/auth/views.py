# coding: utf-8
from . import auth
from flask_login import current_user
from flask import request, redirect, url_for, render_template, flash
from .form import LoginForm, RegistrationForm, Password_Reset_Form, \
    Password_Reset_Request_Form, Change_Email_Form, ChangePasswordForm
from ..models import User
from flask_login import login_user,login_required,logout_user,current_user


@auth.before_app_request()
def before_request():
    if current_user.is_authenticated:
        current_user.ping()  # refresh the timestamp
        if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.'  # ?


@auth.route('/unconfirmed')
def uncofirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remeber_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))  # ?
        flash('用户名或密码不正确！')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('你已经登出！')
    return redirect(url_for('main.index'))

@auth.route('/register',methods=['GET','POSTS'])
def register():
    form=RegistrationForm()
    if form.validate_on_submit():
        user=User(email=form.email.data,
                  )


    return render_template('auth/register.html',form=form)





