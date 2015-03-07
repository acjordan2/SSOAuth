from flask import Blueprint, render_template, request, jsonify
from flask.ext.login import login_required, current_user
from werkzeug.security import gen_salt
from models import db, Client

client = Blueprint('client', __name__)

@client.route('/client/add')
@login_required
def addClient():
    item = Client(
        client_id = gen_salt(40),
        client_secret = gen_salt(50),
        client_name = "Test OAuth Client",
        client_description = "OAuthclient Used for testing purposes",
        _redirect_uris = ' '.join([
            'http://localhost:8000/authorized',
            'http://127.0.0.1:8000/authorized'
        ]),
        _default_scopes='email',
        user_id = current_user.id
    )
    db.session.add(item)    
    db.session.commit()
    return jsonify(
        client_id = item.client_id,
        client_secret = item.client_secret
    )
