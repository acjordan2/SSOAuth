import bcrypt
from flask import Blueprint, render_template, redirect, request
from wtforms import fields, validators
from flask.ext.wtf import Form
from flask.ext.login import LoginManager, login_required, current_user, flash, url_for, login_user, logout_user
from models import db, User

account = Blueprint('account', __name__)
login_manager = LoginManager()

login_manager.login_view = "account.login"

class LoginForm(Form):
    username = fields.TextField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_login(self, field):
        user = self.get_user()
        
        if user is None:
            raise validators.validationError('Invalid user or password')
        
        if not bcrypt.hashpw(self.password.data, user.password) == user.password:
            raise validators.ValidationError('Invalid user or password')

    def get_user(self):
        return db.session.query(User).filter_by(login_self.login.data).first()

class RegistrationForm(Form):
    login = fields.TextField(validators=[validators.required()])
    email = fields.TextField()
    password = fields.PasswordField(validators=[validators.required()])

    def validate_login(self, field):
        if db.session.query(User).filter_by(login=self.login.data).count() > 0:
            raise validators.ValidationError('Duplicate username')

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@account.record_once
def on_load(state):
    login_manager.init_app(state.app)
    db.init_app(state.app)

@account.route('/account')
@login_required
def profile():
    return render_template('account/profile.html', current_user=current_user)

@account.route('/account/settings')
@login_required
def settings():
    return render_template('account/settings.html')

@account.route('/account/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('account/register.html')
    user = User(request.form['username'], bcrypt.hashpw(request.form['password'], bcrypt.gensalt()), request.form['email'])
    db.session.add(user)
    db.session.commit()
    flash('User Successfully Registered')
    return redirect(url_for('account.login'))

@account.route('/account/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated() == True:
        return redirect('/account')    

    if request.method == 'GET':
        return render_template('account/login.html')
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Username or Password is invalid')
    
    if bcrypt.hashpw(password, user.password) == user.password:
        login_user(user)
        flash("Logged in successfully")
        return redirect('/account')
    return render_template('account/login.html')

@account.route('/account/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('account.login'))
