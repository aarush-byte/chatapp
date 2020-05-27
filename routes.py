from flask import render_template, url_for, flash, redirect, request
from flaskblog.__inet__ import app, bcrypt, db
from flaskblog.forms import RegistrationForm, LoginForm
from flaskblog.database import User, Post
from flask_login import login_user, current_user, logout_user, login_required


posts = [
    {
        'author': 'Aarush',
        'title': 'Blog Post 1',
        'content': 'First post content',
        'date_posted': 'April 20, 2018'
    },
    {
        'author': 'Surya',
        'title': 'Blog Post 2',
        'content': 'Second post content',
        'date_posted': 'April 21, 2018'
    }
]


@app.route('/')
@app.route('/home')
def home():
   return render_template('home.htm', posts=posts)

@app.route('/about')
def about():
    return render_template('about.htm')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created! You are now able to Log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.htm', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return  redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('login Unsuccessful.Please Check Your email and password', 'danger')    
    return render_template('login.htm', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account")
@login_required
def account():
    return render_template('account.htm', title='Account')
