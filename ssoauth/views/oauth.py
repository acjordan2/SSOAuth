from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask.ext.login import current_user, login_required
from flask_oauthlib.provider import OAuth2Provider
from models import db, Client, Grant, Token

oauth = Blueprint('oauth', __name__)
provider = OAuth2Provider(current_app)

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
        _scopes=token['scopes'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id
    )

    db.session.add(tok)
    db.session.commit()
    return tok

@oauth.route('/oauth/token')
@provider.authorize_handler
def access_token():
    return None

@oauth.route('/oauth/authorize', methods=['GET', 'POST'])
@provider.authorize_handler
@login_required
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)
    
    confirm = reqeust.form.get('confirm', 'no')
    return confirm

@oauth.route('/api/me')
@provider.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username)
