from flask import Flask, redirect, url_for, render_template, flash, session, \
    current_app, request, abort
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
current_user
from flask_cors import CORS
from dotenv import load_dotenv
from urllib.parse import urlencode
import os, secrets, requests, uuid
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = './static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf'}
app = Flask(__name__)
app.secret_key = os.getenv('SUPER_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:root@localhost:5432/sf"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)
CORS(app, support_credentials=True)

class FilesList(db.Model):
    __tablename__ = 'fileslist'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4())
    name = db.Column(db.String())

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"<File {self.name}>"

@app.route('/fileslists', methods=['POST', 'GET'])
def handle_fileslists():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_list = FilesList(name=data['name'])
            db.session.add(new_list)
            db.session.commit()
            return {"message": f"list {new_list.name} has been created successfully."}
        else:
            return {"message": "The request payload is not a JSON format"}
    
    elif request.method == 'GET':
        lists = FilesList.query.all()
        results = [
            {
                "id": list.id,
                "name": list.name,
            } for list in lists
        ]
        return {"count": len(results), "lists": results}

@app.route('/fileslists/<id>', methods=['GET', 'PUT', 'DELETE'])
def handle_filslists(id):
    list = FilesList.query.get_or_404(id)

    if request.method == 'GET':
        response = {
            "id": list.id,
            "name": list.name,
        }
        return {"list": response}
    
    elif request.method == 'PUT':
        data = request.get_json()
        list.id = data['id']
        list.name = data['name']
        db.session.add(list)
        db.session.commit()
        return {"message": f"list {list.name} successfully updated"}
    
    elif request.method == "DELETE":
        db.session.delete(list)
        db.session.commit()
        return {"message": f"List {list.name} successfully deleted."}
    

# FILE

class File(db.Model):
    __tablename__ = 'file'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4())
    name = db.Column(db.String())
    description = db.Column(db.String())
    list_id = db.Column(UUID(as_uuid=True))
    url = db.Column(db.String())

    def __init__(self, name, description, url, file):
        self.name = name
        self.description = description
        self.url = url
        self.file = file

    def __repr__(self):
        return f"<File {self.name}>"


@app.route('/files', methods=['POST', 'GET'])
def handle_files():
    if request.method == 'POST':
        if request.is_json or request.files:
            file = request.files['file']
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            data = request.get_json()
            new_file = File(name=data['name'], description=data['description'], url=file_path)
            db.session.add(new_file)
            db.session.commit()
            return {"message": f"file {new_file.name} has been created successfully."}
        else:
            return {"message": "The request payload is not a JSON format"}

    elif request.method == 'GET':
        files = File.query.all()
        results = [
            {
                "id": file.id,
                "name": file.name,
                "description": file.description,
                "list_id": file.list_id,
                "url": file.url
            } for file in files
        ]
        return {"count": len(results), "files": results}


# OAUTH
    
load_dotenv()

app.config['OAUTH2_PROVIDERS'] = {
    # Google OAuth 2.0 documentation:
    # https://developers.google.com/identity/protocols/oauth2/web-server#httprest
    'google': {
        'client_id': os.getenv('GOOGLE_CLIENT_ID'),
        'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
        'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
        'token_url': 'https://accounts.google.com/o/oauth2/token',
        'userinfo': {
            'url': 'https://www.googleapis.com/oauth2/v3/userinfo',
            'email': lambda json: json['email'],
        },
        'scopes': ['https://www.googleapis.com/auth/userinfo.email'],
    },

}

login = LoginManager(app)
login.login_view = 'index'



class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4())
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=True)
@login.user_loader
def load_user(id):
    return db.session.get(User, id)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))





@app.route('/authorize/<provider>')
def oauth2_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)

    # generate a random string for the state parameter
    session['oauth2_state'] = secrets.token_urlsafe(16)

    # create a query string with all the OAuth2 parameters
    qs = urlencode({
        'client_id': provider_data['client_id'],
        'redirect_uri': url_for('oauth2_callback', provider=provider,
                                _external=True),
        'response_type': 'code',
        'scope': ' '.join(provider_data['scopes']),
        'state': session['oauth2_state'],
    })

    # redirect the user to the OAuth2 provider authorization URL
    return redirect(provider_data['authorize_url'] + '?' + qs)


@app.route('/callback/<provider>')
def oauth2_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)

    # if there was an authentication error, flash the error messages and exit
    if 'error' in request.args:
        for k, v in request.args.items():
            if k.startswith('error'):
                flash(f'{k}: {v}')
        return redirect(url_for('index'))

    # make sure that the state parameter matches the one we created in the
    # authorization request
    if request.args['state'] != session.get('oauth2_state'):
        abort(401)

    # make sure that the authorization code is present
    if 'code' not in request.args:
        abort(401)

    # exchange the authorization code for an access token
    response = requests.post(provider_data['token_url'], data={
        'client_id': provider_data['client_id'],
        'client_secret': provider_data['client_secret'],
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('oauth2_callback', provider=provider,
                                _external=True),
    }, headers={'Accept': 'application/json'})
    if response.status_code != 200:
        abort(401)
    oauth2_token = response.json().get('access_token')
    if not oauth2_token:
        abort(401)

    # use the access token to get the user's email address
    response = requests.get(provider_data['userinfo']['url'], headers={
        'Authorization': 'Bearer ' + oauth2_token,
        'Accept': 'application/json',
    })
    if response.status_code != 200:
        abort(401)

    email = provider_data['userinfo']['email'](response.json())

    # find or create the user in the database
    user = db.session.scalar(db.select(User).where(User.email == email))
    if user is None:
        user = User(email=email, username=email.split('@')[0])
        db.session.add(user)
        db.session.commit()

    # log the user in
    login_user(user)
    return redirect(url_for('index'))

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(port=8000, debug=True)