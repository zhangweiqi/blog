from . import main
from .forms import PostForm
from flask import current_app, abort, render_template
from flask_login import current_user
from ..models import Permission, User, Role, Post, Comment
from .. import db
from flask import redirect,url_for,request


@main.after_app_request()
def after_request():


@main.route('/shutdown')
def server_shutdown():


@main.route('/', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        post = Post(body =form.post.data,author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('main.index'))
    page=request.args.get('page',1,type=int)
    show_followed=False
    if current_user.is_authenticated:
        show_followed=bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query=current_user.followed_posts
    else:
        query=Post.query
    pagination=query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False
    )
    posts=pagination.items
    return render_template('index.html',form=form,posts=posts,
                           show_followed=show_followed,pagination=pagination)

@main.route('/user/<username>')
def user(username):


















