from flask import Flask, render_template, redirect, url_for, flash, request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

CURRENT_USER_ID = None

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CONFIGURE TABLES
class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    # This will act like a list of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship('BlogPost', back_populates="author")

    comments = relationship('Comment', back_populates="author")


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refer to the table name of the User.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create references to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)


db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    is_admin = False
    if CURRENT_USER_ID == 1:
        is_admin = True
    return render_template("index.html", all_posts=posts, is_admin=is_admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if request.method == "POST":
        email = register_form.email.data
        password = register_form.password.data
        name = register_form.name.data

        user = User.query.filter_by(email=request.form.get("email")).first()

        if user:
            flash("You've already signup with that email, log in instead.")
            return redirect(url_for('login'))

        hashed_and_salted_password = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=8
        )
        new_user = User(
            email=email,
            password=hashed_and_salted_password,
            name=name
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        global CURRENT_USER_ID
        CURRENT_USER_ID = new_user.id
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if request.method == "POST":
        email = login_form.email.data
        password = login_form.password.data

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("The email does not exist, please try again.")
            return redirect(url_for('login'))

        if check_password_hash(user.password, password):
            login_user(user)
            global CURRENT_USER_ID
            CURRENT_USER_ID = user.id
            return redirect(url_for('get_all_posts'))
        else:
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form)


def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with route function
        return func(*args, **kwargs)
    return decorated_function


@app.route('/logout')
def logout():
    logout_user()
    global CURRENT_USER_ID
    CURRENT_USER_ID = None
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    blog_comments = Comment.query.filter_by(post_id=post_id)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("Please login to make a comment.")
            return redirect(url_for('login'))
        comment = comment_form.comment.data
        new_comment = Comment(
            author_id=current_user.id,
            post_id=post_id,
            text=comment
        )
        db.session.add(new_comment)
        db.session.commit()
    is_admin = False
    if CURRENT_USER_ID == 1:
        is_admin = True
    return render_template(
        "post.html",
        post=requested_post,
        is_admin=is_admin,
        form=comment_form,
        comments=blog_comments
    )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == "POST":
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                author_id=current_user.id,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
