# coding: utf-8
from . import main
from .forms import PostForm, EditProfileAdminForm, EditProfileForm, CommentForm
from flask import current_app, abort, render_template, make_response
from flask_login import current_user, login_required
from ..models import Permission, User, Role, Post, Comment
from .. import db
from flask import redirect, url_for, request, flash
from ..decorators import admin_required, permission_required
from flask_sqlalchemy import get_debug_queries


@main.after_app_request
def after_request(response):  # ?
    for query in get_debug_queries():
        if query.duration >= current_app.config['SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response


@main.route('/shutdown')
def server_shutdown():
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'


@main.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post = Post(body=form.post.data, author=current_user._get_current_object())
        db.session.add(post)  # current_user is a slight packaging of the user,
        return redirect(url_for('main.index'))  # so we need use "_get_current_object"
        # to get real current_user.
    page = request.args.get('page', 1, type=int)  # If args can't transform to int, return default=1.
    show_followed = False  # return all posts or followed_posts.
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        main_post = current_user.followed_posts
    else:
        main_post = Post.query
    pagination = main_post.order_by(Post.timestamp.desc()).paginate(  # desc=descend
        page, per_page=current_app.config['POSTS_PER_PAGE'],
        error_out=False)  # If the request page beyonds the range:
# True:return 404; False:return a empty list.
    each_page_posts = pagination.items
    return render_template('index.html', form=form, posts=each_page_posts,
                           show_followed=show_followed, pagination=pagination)


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['POSTS_PER_PAGE'],
        error_out=False)
    each_page_posts = pagination.items
    return render_template('user_1.html', user=user, posts=each_page_posts,
                           pagination=pagination)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.introduction = form.introduction.data
        db.session.add(current_user)
        flash('你的资料已更新！')
        return redirect(url_for('main.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.introduction.data = current_user.introduction
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = user.role.data
        user.name = user.name.data
        user.location = user.location.data
        user.introduction = form.introduction.data
        db.session.add(user)
        flash('用户资料已更新！')
        return redirect(url_for('main.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.introduction = user.introduction
    return render_template('edit_profile.html', form=form, user=user)


@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          post=post,
                          author=current_user._get_current_object())
        db.session.add(comment)
        flash('评论已提交！')
        return redirect(url_for('main.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) // \
               current_app.config['COMMENT_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['COMMENT_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('post.html', posts=[post], form=form,
                           comments=comments, pagination=pagination)


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash('文章修改成功！')
        return redirect(url_for('main.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)


@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    """
    Users begin to follow 'username's user.
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('用户不存在！')
        return redirect(url_for('main.index'))
    if current_user.is_following(user):
        flash('你已经关注该用户！')
        return redirect(url_for('main.user', username=username))
    current_user.follow(user)
    flash('现在你已经关注他了！')
    return redirect(url_for('main.user', username=username))


@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    """
    Cancel follow 'username's user
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('用户不存在！')
        return redirect(url_for('main.index'))
    if not current_user.is_following(user):
        flash('你没有关注该用户！')
        return redirect(url_for('index.user', username=username))
    current_user.unfollow(user)
    flash('你已经取消对该用户的关注！')
    return redirect(url_for('main.user', username=username))


@main.route('/follower/<username>')
def followers(username):
    """
    show the followers of the user of the username.
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('用户不存在！')
        return redirect(url_for('main.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.follower.paginate(
        page, per_page=current_app.config['FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]  # ?
    return render_template('followers.html', user=user, title="Followers of",
                           endpoint='.followers', pagination=pagination,
                           follows=follows)


@main.route('/followed/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('用户不存在！')
        return redirect(url_for('main.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.pagination(
        page, per_page=current_app.config['FOLLOWEDS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]  # ?
    return render_template('followeds.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)


@main.route('/all')
@login_required
def show_all():  # set local cookie  max_age=day hour min second
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('show_followed', '', max_age=30 * 24 * 60 * 60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('main.index')))
    resp.set_cookie('show_followed', '1', max_age=30 * 24 * 60 * 60)
    return resp


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['COMMENTS_PER_PAGE_MODERATE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
                           pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))
