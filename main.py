import is_safe_url
import sqlalchemy.exc
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, UserRegisterForm, LoginForm, CommentForm, PasswordChange
from flask_gravatar import Gravatar
from dotenv import load_dotenv
import os
from functools import wraps
import bleach

load_dotenv('./.env')

app = Flask(__name__)
# app.config['SECRET_KEY'] = os.getenv('BWU-API-Key')
# This line allows this app to use Heroku's Config Vars environment variable for SECRET_KEY.
app.config['SECRET_KEY'] = os.getenv('BWU-API-Key')
app.config['TRAP_BAD_REQUEST_ERRORS'] = True
ckeditor = CKEditor(app)
Bootstrap(app)

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

##CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
# This line will allow this app to use Heroku's Postgres Database.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(500), nullable=False)
    last_name = db.Column(db.String(500), nullable=True)
    blog_posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='commenter')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='blog_posts')
    comments = relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=True)
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    commenter = relationship('User', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')


# db.create_all()

# strips invalid tags/attributes
def strip_invalid_html(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
                    'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul']

    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }

    cleaned = bleach.clean(content,
                           tags=allowed_tags,
                           attributes=allowed_attrs,
                           strip=True)

    return cleaned


# Initialization of Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# Flask-WTF

def admin_only(func):
    @wraps(func)
    def any_func(*args, **kwargs):
        if current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)

    return any_func


@login_manager.user_loader
def load_user(user_id: int):
    return User.query.get(int(user_id))


# noinspection PyBroadException
def redirect_destination(fallback):
    destination = request.args.get('next')
    if not is_safe_url.is_safe_url(destination, allowed_hosts='http://127.0.0.1:5000/'):
        try:
            return redirect(url_for('get_all_posts'))
        except Exception:
            return abort(400)
    # noinspection PyBroadException
    try:
        redirect(destination)
    except Exception:
        return redirect(fallback)
    return redirect(destination)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = UserRegisterForm()

    if request.method == 'POST':
        if register_form.validate_on_submit():
            try:
                new_user = User()
                new_user.first_name = register_form.first_name.data
                new_user.last_name = register_form.last_name.data
                new_user.email = register_form.email.data
                new_user.password = generate_password_hash(register_form.password.data, method='pbkdf2:sha256',
                                                           salt_length=11)
                db.session.add(
                    new_user
                )
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('get_all_posts'))
            except sqlalchemy.exc.IntegrityError:
                flash('Cannot add user!  Email may have already existed!', 'email error')
                return render_template('register.html', register_form=register_form)
    return render_template("register.html", register_form=register_form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if request.method == 'POST':
        user_email = login_form.email.data
        user_password = login_form.password.data
        correct_email = User.query.filter_by(email=user_email).first()
        if correct_email:
            user_hashed_passwd = check_password_hash(correct_email.password, user_password)
            if user_hashed_passwd:
                login_user(correct_email)
                flash('Login successfully!', 'login message')
                return redirect_destination(fallback=url_for('get_all_posts'))
            else:
                flash('Incorrect password!  Try again!', 'password error')
                return redirect_destination(fallback=url_for('login'))
        else:
            flash('Email not found!', 'email error')
            return redirect_destination(fallback=url_for('login'))
    return render_template('login.html', login_form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    requested_comments = Comment.query.filter_by(post_id=requested_post.id).all()
    if request.method == 'POST':
        if comment_form.validate_on_submit():
            if not current_user.is_authenticated:
                flash('You must sign in to write comments!', 'comment error')
                return redirect(url_for('login'))
            else:
                new_comment = Comment(
                    text=strip_invalid_html(comment_form.comment_body.data),
                    commenter=current_user,
                    parent_post=requested_post
                )
                db.session.add(new_comment)
                db.session.commit()
                return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, comment_form=comment_form,
                           requested_comments=requested_comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            new_post = BlogPost(
                title=str(form.title.data),
                subtitle=str(form.subtitle.data),
                author=current_user,
                body=form.body.data,
                img_url=str(form.img_url.data),
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if request.method == 'POST':
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/delete_comment/<int:comment_id>/<int:post_id>')
@login_required
@admin_only
def delete_comment(comment_id, post_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


@app.route('/test')
@login_required
def test():
    return render_template('test.html')


@app.route('/passwd_change_for_admin', methods=['POST', 'GET'])
@login_required
@admin_only
def passwd_change_for_admin():
    change_admin_password_form = PasswordChange()
    admin_object = User.query.filter_by(id=1).first()
    if request.method == 'POST':
        if change_admin_password_form.validate_on_submit():
            new_password = change_admin_password_form.password.data
            confirm_new_password = change_admin_password_form.confirm_password.data
            if new_password == confirm_new_password:
                admin_object.password = generate_password_hash(new_password, method='pbkdf2:sha256',
                                                               salt_length=11)
                db.session.commit()
                flash('Your password had been changed successfully!', 'password change message')
                return redirect(url_for('get_all_posts'))
    return render_template('password_change.html', change_admin_password_form=change_admin_password_form)


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    app.run(debug=False)
