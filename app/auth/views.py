# coding: utf-8
from . import auth
from flask_login import current_user
from flask import request, redirect, url_for, render_template, flash
from .form import LoginForm, RegistrationForm, Password_Reset_Form, \
    Password_Reset_Request_Form, Change_Email_Form, ChangePasswordForm
from ..models import User
from flask_login import login_user, login_required, logout_user, current_user
from .. import db
from ..email import send_email


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


@auth.route('/register', methods=['GET', 'POSTS'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, '验证你的账户',
                   'auth/email/confirm', user=user, token=token)
        flash('一封验证邮件已被发送至你的邮箱！')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('你已成功验证了你的账户，谢谢!')
    else:
        flash('验证链接已失效或过期！')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, '验证你的账户',
               'auth/email/confirm', user=current_user, token=token)
    flash('一封新的验证邮件已被发往你的邮箱！')
    return redirect(url_for('main.index'))


@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            flash('您的密码已更新！')
            return redirect(url_for('main.index'))
        else:
            flash('旧密码错误！')
    return render_template('auth/chagne_password.html', form=form)


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():  # ?form:  only email
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = Password_Reset_Request_Form()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, '重设密码',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
        flash('一封包含重设密码指令的的邮件已经发往你的邮箱！')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = Password_Reset_Form()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('你的密码已更新！')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = Change_Email_Form()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, '验证邮箱地址', 'auth/email/change_email',
                       user=current_user, token=token)
            flash('一封验证新邮箱地址的邮件已发往你的新邮箱！')
            return redirect(url_for('main.index'))
        else:
            flash('密码错误！')
    return render_template('auth/change_email.html', form=form)


@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash('你的邮箱地址已更新！')
    else:
        flash('无效请求！')
    return redirect(url_for('main.index'))
