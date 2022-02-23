import os

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
import secrets
from functools import wraps
# Import RegisterForm from forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


# ----------------------------------------------------------------------------------------
# Setup Server:
app = Flask(__name__)
# app.config['SECRET_KEY'] = secrets.token_hex()
# app.config['SECRET_KEY'] = 'gvskjgon54.rtog-a6847snjft64rhs-gbdf'
app.config['SECRET_KEY'] = os.environ.get('CSRF')
ckeditor = CKEditor(app)


# ----------------------------------------------------------------------------------------
# Include Bootstrap
Bootstrap(app)


# ----------------------------------------------------------------------------------------
#Setup Gravatar (Image generation from email address)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# ----------------------------------------------------------------------------------------
# # CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog_relations.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog_relations.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ----------------------------------------------------------------------------------------
# Initialize LogIn Manager:
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    # return User.get(user_id)
    return User.query.get(int(user_id))


def admin_only(function):
    """ Decorator function to restrict sites / functions to the admin"""
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return function(*args, **kwargs)
        else:
            print('nicht der admin !')
            abort(403)
    return decorated_function


# ----------------------------------------------------------------------------------------
# # CONFIGURE TABLES
class User(UserMixin, db.Model):
    """
    Relationships: (one parent mapped to many children, bidirectional):
        - Parent of class/table BlogPost;   relation A (1-to-many relationship)
        - Parent of class/table Comment;    relation B (1-to-many relationship)
        """
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    # Relationship A, parent:
    posts = relationship("BlogPost", back_populates="author")
    # Relationship B, parent:
    comments = relationship("Comment", back_populates="author_comment")


class BlogPost(db.Model):
    """
    Relationships (one parent mapped to many children, bidirectional):
        - Child of class/table User;        relation A (1-to-many, bidirectional relationship)
        - Parent of class/table Comment;    relation C (1-to-many, bidirectional relationship)
        """
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Relationship A, child:
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Relationship B, parent:
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    """
    Relationship (one parent mapped to many children, bidirectional):
        - Child of class/table User         relationship B (1-to-many, bidirectional relationship)
        - Child of class/table BlogPost;    relationship C (1-to-many, bidirectional relationship)
        """
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # Relationship B, child:
    author_comment_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author_comment = relationship("User", back_populates="comments")
    # Relationship C, child:
    parent_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


db.create_all()


# ----------------------------------------------------------------------------------------
# Home route
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


# ----------------------------------------------------------------------------------------
# One post
@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(parent_post_id=post_id)
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                author_comment = current_user,
                parent_post = requested_post,
                text=comment_form.body.data
            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, comments=comments, form=comment_form)
        else:
            flash("Please login to enable commenting")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, comments=comments, form=comment_form)


# ----------------------------------------------------------------------------------------
# Login management routes:
@app.route('/register', methods=['POST', 'GET'])
def register():
    registration_form = RegisterForm()
    if registration_form.validate_on_submit():
        if User.query.filter_by(email=registration_form.email.data).first():
            flash('The email is already registered, please login.')
            return redirect(url_for('login'))
        else:
            pw_secured = generate_password_hash(
                password=registration_form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                name=registration_form.name.data,
                email=registration_form.email.data,
                password=pw_secured
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=registration_form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        login_email = login_form.email.data
        login_pw_plain = login_form.password.data
        user = User.query.filter_by(email=login_email).first()
        if user:
            if check_password_hash(user.password, login_pw_plain):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('This password is not assigned to this email address...')
                # return render_template("login.html")
        else:
            flash('This email is not assigned to a user account.')
            # return render_template("login.html")
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# ----------------------------------------------------------------------------------------
# Post creation / edit routes
@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    post_form = CreatePostForm()
    if post_form.validate_on_submit():
        new_post = BlogPost(
            title=post_form.title.data,
            subtitle=post_form.subtitle.data,
            body=post_form.body.data,
            img_url=post_form.img_url.data,
            # author=current_user.name,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=post_form, is_edit=False)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = current_user.name
        post.author = current_user
        post.body = edit_form.body.data
        post.date = date.today().strftime("%B %d, %Y")
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# ----------------------------------------------------------------------------------------
@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


# ----------------------------------------------------------------------------------------
# main
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
