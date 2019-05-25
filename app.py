from flask import Flask, render_template, redirect, session, flash, request
from sqlalchemy.sql import func
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import re

app = Flask(__name__)
app.secret_key = "secret!"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 
Bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quotes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

likes_table = db.Table('likes', 
            db.Column('user_id', 
                    db.Integer, 
                    db.ForeignKey('users.id'),
                    primary_key=True),
            db.Column('post_id',
                    db.Integer,
                    db.ForeignKey('posts.id'),
                    primary_key=True)
            )

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(
        db.Integer, 
        primary_key=True, 
        autoincrement=True
    )
    first_name = db.Column(
        db.String(255)
    )
    last_name = db.Column(
        db.String(255)
    )
    username = db.Column(
        db.String(255)
    )
    email = db.Column(
        db.String(255)
    )
    password = db.Column(
        db.String(255)
    )
    created_at = db.Column(
        db.DateTime,
        server_default=func.now()
    )
    updated_at = db.Column(
        db.DateTime,
        server_default=func.now(),
        onupdate=func.now()
    )
    post_user_like = db.relationship('Post',
        secondary=likes_table
    )
    
    @classmethod
    #validate registration 
    def register_validations(cls, form):
        errors = []
        #also can use valid = True & valid = False
        if len(form['first_name']) < 2:
            errors.append('First name must be at least 2 characters long!')
        if len(form['last_name']) < 2:
            errors.append('Last name must be at least 2 characters long!')
        if not EMAIL_REGEX.match(form['email']):
            errors.append('Please enter valid Email address')
        if form['password'] != form['confirm']:
            errors.append('Password must be match')
        #minimum password character
        if len(form['password']) < 6:
            errors.append('Your password must be at least 6 characters long!')
        #need at least one number 
        elif re.search('[0-9]', form['password']) is None:
            errors.append('You need at least one number')
        #need at least one Capital letter
        elif re.search('[A-Z]', form['password']) is None:
            errors.append('You need at least one Captial letter')
        #check if there is same email address registered already
        existing_emails = cls.query.filter_by(email=form['email']).first()
        if existing_emails:
            errors.append("Email already in use! please log in")
        #username validation
        if len(form['username']) < 5:
            errors.append('Username must be at least 5 characters long!')
        #check if there is same username
        existing_usernames = cls.query.filter_by(username=form['username']).first()
        if existing_usernames:
            errors.append('Username already in use. Please enter another Username')

        return errors

    #add users to the data
    @classmethod
    def create_user(cls, form):
        pw_hash = Bcrypt.generate_password_hash(form['password'])
    #user's information that need to be add to the data
        user = cls(
            first_name = form['first_name'],
            last_name = form['last_name'],
            username = form['username'],
            email = form['email'],
            password = pw_hash,
        )
        db.session.add(user)
        db.session.commit()
        return user.id

    #logn validation
    @classmethod
    def login_validations(cls, form):
        user = cls.query.filter_by(email=form['email']).first()
        if user:
            if Bcrypt.check_password_hash(user.password, form['password']):
                return (True, user.id)
        return (False, "Email or password is incorrect.")

    @classmethod 
    def login_user(cls, user_id):
        login_user = cls.query.filter_by(id = user_id).all()
        return login_user[0]

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True
    )
    content = db.Column(
        db.String(255)
    )
    created_at = db.Column(
        db.DateTime,
        server_default=func.now()
    )
    updated_at = db.Column(
        db.DateTime,
        server_default=func.now(),
        onupdate=func.now()
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=False
    )
    user = db.relationship(
        'User',
        foreign_keys=[user_id],
        backref='user_Post'
    )
    user_who_like_post = db.relationship(
        'User',
        secondary=likes_table
    )
    
    #check if users write post
    @classmethod
    def post_validation(cls, form):
        errors = []
        if len(form['content']) < 1:
            errors.append('Post must be at least 1 character')
        return errors
    
    #add new post
    @classmethod
    def add_new_post(cls, form, user_id):
        add_post = cls(
            content = form['content'],
            user_id = user_id
        )
        db.session.add(add_post)
        db.session.commit()
        return add_post

    #see all post
    @classmethod
    def all_post(cls):
        return cls.query.all()

    #get all the post from users
    @classmethod
    def get_user_post(cls, user_id):
        get_users_post = cls.query.filter_by(user_id = user_id).all()
        return get_users_post

    @classmethod
    def add_like(cls, user_id, post_id):
        user_like_post = cls.query.get(post_id)
        user = User.query.get(user_id)
        user_like_post.user_who_like_post.append(user)
        db.session.commit()
        
    @classmethod
    def get_post(cls, post_id):
        get_single_post = cls.query.filter_by(id = post_id).first()
        return get_single_post

    @classmethod
    def delete_post(cls, post_id):
        get_single_post = cls.query.get(post_id)
        db.session.delete(get_single_post)
        db.session.commit()



#homepage that user can register/ login
@app.route('/')
def root():
    if 'user_id' not in session:
        return redirect('/new')
    return redirect('/dashboard')

@app.route('/new')
def register():
    return render_template('homepage.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    all_post = Post.all_post()
    current_user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=current_user, posts = all_post)

@app.route('/users/create', methods=['POST'])
def new_user():
    register = User.register_validations(request.form)
    if register:
        for error in register:
            flash(error)
        return redirect('/')
    user_id = User.main_user(request.form)
    session['user_id'] = user_id
    return redirect('/dashboard')

@app.route('/users/login', methods=['POST'])
def user_login():
    valid, response = User.login_validations(request.form)
    if not valid:
        flash(response)
        return redirect('/')
    session['user_id'] = response
    return redirect('/dashboard')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/posts') #bright_ideas
def post():
    all_post = Post.all_post()

    user_info = User.login_user(session['user_id'])

    current_user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user_info = user_info, posts = all_post, user = current_user )

@app.route('/posts/create', methods=['POST'])
def add_post(): #add_post
    errors = Post.post_validation(request.form)
    if errors:
        for error in errors:
            flash(error)
    Post.add_new_post(request.form, session['user_id'])
    return redirect('/posts')

@app.route('/user/<user_id>')
def user_info(user_id): #user
    user_info = User.login_user(user_id)
    get_user_post = Post.get_user_post(user_id)
    print(get_user_post)
    count_all_post_like = 0
    for each_post in get_user_post:
        count_all_post_like += len(each_post.user_who_like_post)
    
    print(count_all_post_like)

    return render_template(
        'likes.html', 
        user_info = user_info, 
        count_all_post_like = count_all_post_like, 
        count_user_post = len(get_user_post)
        )

@app.route('/posts/<post_id>/like')
def like(post_id): #like
    Post.add_like(session['user_id'], post_id)
    return redirect('/posts')

@app.route('/posts/<post_id>')
def user_post(post_id): #post
    post = Post.get_post(post_id)
    return render_template("post.html", post = post)

@app.route('/posts/<post_id>/delete') #delete
def delete(post_id):
    Post.delete_post(post_id)
    return redirect('/posts')


if __name__ == "__main__":
    app.run(debug=True)
