import bcrypt, random, string, base64, os

from datetime import datetime, timedelta
from flask import Flask
from flask import session, request
from flask import render_template, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import gen_salt
from flask_oauthlib.provider import OAuth2Provider
from server.shared.models import db
from server.models import User, Client, Grant, Token, Group


app = Flask(__name__, template_folder='templates')
app.debug = True
app.secret_key = 'secret'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db.init_app(app)
oauth = OAuth2Provider(app)

def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None

@app.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user:
            password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
            user = User(username=username, password=password_hash)
            db.session.add(user)
            db.session.commit()
            session['id'] = user.id
        elif bcrypt.hashpw(password, user.password) == user.password:
            sess = base64.encodestring(os.urandom(48))
            print sess
            session['id'] = user.id
            session['username'] = user.username
            return redirect('/')
    user = current_user()
    return render_template('home.html', user=user)

@app.route('/createGroup', methods=('GET', 'POST'))
def createGroup():
    message = ""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        group = Group.query.filter_by(name=name).first()
        if not group:
            group = Group(name=name, description=description)
            db.session.add(group)
            db.session.commit()
            message = "Group created"
        else:
            message = "Group name already in use, please be more creative"
    return render_template('createGroup.html', message=message)

@app.route('/client')
def client():
    user = current_user()
    if not user:
        return redirect('/')
    item = Client(
        client_id = gen_salt(40),
        client_secret = gen_salt(50),
        client_name = 'Test OAuth Client',
        client_description = "OAuth client used for testing purpose",
        _redirect_uris=' '.join([
            'http://localhost:8000/authorized',
            'http://127.0.0.1:8000/authorized',
            'http://127.0.1:8000/authorized',
            'http://127.1:8000/authorized',
        ]),
        _default_scopes='email',
        user_id = user.id,    
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(
        client_id = item.client_id,
        client_secret=item.client_secret,
    )

@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()

@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()

@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok


@app.route('/oauth/token')
@oauth.token_handler
def access_token():
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
#        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return True 


    


@app.route('/api/me')
@oauth.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username, password=user.password)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0')
