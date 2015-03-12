import redis
from datetime import datetime, timedelta
from flask import Flask
from flask import render_template, redirect, request, jsonify
from flask.ext.login import login_required, current_user
from flask_kvsession import KVSessionExtension
from simplekv.memory.redisstore import RedisStore
from flask_oauthlib.provider import OAuth2Provider


from views.account import account
from views.client import client
from views.oauth import oauth
from models import db, Client, Grant, Token



store = RedisStore(redis.StrictRedis())

app = Flask(__name__, instance_relative_config=True, template_folder='templates')
app.config.from_object('config')
app.config.from_pyfile('config.py')

KVSessionExtension(store, app)
provider = OAuth2Provider(app)


app.register_blueprint(account)
app.register_blueprint(client)

@provider.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()

@provider.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()

@provider.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user,
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant

@provider.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()

@provider.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # Make sure every client has only one token connected to a User
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
        user_id=request.user.id
    )

    db.session.add(tok)
    db.session.commit()
    return tok

@app.route('/oauth/token', methods=['GET', 'POST'])
@provider.token_handler
def access_token():
    return None

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@provider.authorize_handler
@login_required
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = current_user
        return render_template('authorize.html', **kwargs)
    
    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

@app.route('/api/me')
@provider.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username)



@app.route('/')
@login_required
def index():
    return redirect('/account')

with app.app_context():
        db.create_all()
app.run()
