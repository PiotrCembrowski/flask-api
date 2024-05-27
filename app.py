from flask import Flask, redirect, url_for, render_template, flash, session, \
    current_app, request, abort, Blueprint, jsonify, send_from_directory, send_file
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, create_engine, MetaData
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Session as sql_session
from sqlalchemy.sql import text
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_cors import CORS
from dotenv import load_dotenv
from urllib.parse import urlencode
import os, secrets, requests, uuid
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
import sentry_sdk

sentry_sdk.init(
    dsn="https://472cbe05f98fa5bd96ca1abd6c521c34@o4507260239609856.ingest.de.sentry.io/4507260242296912",
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    traces_sample_rate=1.0,
    # Set profiles_sample_rate to 1.0 to profile 100%
    # of sampled transactions.
    # We recommend adjusting this value in production.
    profiles_sample_rate=1.0,
)

load_dotenv()
UPLOAD_FOLDER = './static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf'}
app = Flask(__name__, static_folder="./dist", static_url_path='/')
app.config['SECRET_KEY'] = os.getenv('SUPER_SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
# postgres://piotrsf:PSAF1SwXRrN6F2sPTmN6lkC1vFDqbgPc@dpg-co77v2v109ks7383r7jg-a.oregon-postgres.render.com/sf_2ofl
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)
CORS(app, supports_credentials=True)
jwt = JWTManager(app)

# blueprints
view_blueprints = Blueprint('view', __name__, template_folder='templates/views')

# creating engine for ORM sqlalchemy sessions
engine = create_engine(os.getenv('DATABASE_URL'))
metadata = MetaData()

login = LoginManager(app)
login.init_app(app)
login.login_view = 'index'

# OAUTH


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



class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=False)


    def __init__(self, username, email):
        self.username = username
        self.email = email



@login.user_loader
def load_user(id_):
    return db.session.get(User, id_)


@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/admin')
def admin():
    return app.send_static_file('index.html')

@app.route('/signin')
def signin():
    return app.send_static_file('index.html')


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
    login_user(user, remember=False, duration=None, force=False, fresh=True)
    return redirect(url_for('index'))



@app.route('/@me')
def get_current_user():
    user_id = session.get("_user_id")
    
    if not user_id:
        return jsonify(401)
    
    user = User.query.filter_by(id=user_id).first()
    return jsonify(200)



# Files
class FilesList(db.Model):
    __tablename__ = 'fileslist'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String())
    user_id = db.Column(UUID(as_uuid=True))

    def __init__(self, name, user_id):
        self.name = name
        self.user_id = user_id

    def __repr__(self):
        return f"<File {self.name}>"


@app.route('/fileslists', methods=['POST', 'GET'])
def handle_fileslists():
        if request.method == 'POST':
            if current_user.is_authenticated:
                if request.is_json:
                    data = request.get_json()
                    user_id = current_user.get_id()
                    new_list = FilesList(name=data['name'], user_id=user_id)
                    db.session.add(new_list)
                    db.session.commit()
                    return {"message": f"list {new_list.name} has been created successfully."}
                else:
                    return {"message": "The request payload is not a JSON format"}

        elif request.method == 'GET':
            if current_user.is_authenticated:

                user_id = current_user.get_id()

                session = sql_session(engine)
                stmt = select(FilesList).where(FilesList.user_id.in_([user_id]))
                
                results = [
                    {
                        "id": list.id,
                        "name": list.name,
                        "user_id": list.user_id
                    } for list in session.scalars(stmt)
                ]

                return {"count": len(results), "lists": results}



@app.route('/fileslists/<id>', methods=['GET', 'PUT', 'DELETE'])
def handle_fileslists_by_id(id):
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

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String())
    description = db.Column(db.String())
    list_id = db.Column(UUID(as_uuid=True))
    url = db.Column(db.String())

    def __init__(self, name, description, url, list_id):
        self.name = name
        self.description = description
        self.url = url
        self.list_id = list_id

    def __repr__(self):
        return f"<File {self.name}>"
    
    
@app.route('/files/upload', methods=['POST'])
def handle_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return {"message": "Error occurred."}
        if request.files:
            file = request.files['file']
            global file_path
            global file_path_url
            file_path_url = 'empty'
            file_path = 'empty'
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file_path_url = os.path.join('static/uploads', filename)
            file.save(file_path)
            return {"message": f"You've uploaded {file.filename}"}
        else:
            return {"message": "Error occurred."}


@app.route('/files', methods=['POST', 'GET'])
def handle_files():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_file = File(name=data['name'], description=data['description'],
                            url=file_path_url, list_id=data['list_id'])
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



@app.route('/files/<id>', methods=['GET', 'PUT', 'DELETE'])
def handle_files_by_id(id):
    file = File.query.get_or_404(id)

    if request.method == 'GET':
        response = {
            "id": file.id,
            "name": file.name,
        }
        return {"file": response}

    elif request.method == 'PUT':
        data = request.get_json()
        file.id = data['id']
        file.name = data['name']
        db.session.add(file)
        db.session.commit()
        return {"message": f"list {file.name} successfully updated"}

    elif request.method == "DELETE":
        db.session.delete(file)
        db.session.commit()
        return {"message": f"List {file.name} successfully deleted."}
    

# VIEWS

def extract_letters_from_id(id):
    string = id.replace('-','')
    return string.translate(str.maketrans('','','1234567890'))

@app.route('/views/<id>', methods=['GET', 'POST'])
def handle_views(id):

    nameView = extract_letters_from_id(id)

    values = ()
    if request.method == 'POST':
        data = request.get_json()
        for file in data:
            file_id = file['id']
            if len(values) == 0:
                values += (file_id, id)
            else:
                values += (file_id,)

        if len(values) == 0:
            return render_template("/views/error.html")
        with engine.begin() as conn:
            conn.execute(text(""f'CREATE VIEW {nameView} AS SELECT * FROM file WHERE id IN {values};'""))
    
        return render_template(f'/views/view.html', results=values)

    if request.method == 'GET':
        view = []
        with engine.begin() as conn:
            results = conn.execute(text(""f'SELECT * FROM {nameView}'""))
            for row in results:
                view.append(row)
                
        return render_template(f'/views/view.html', results=view)
 
@app.route('/donwload/<id>', methods=['GET']) 
def download(id):
    file = File(name=None, list_id=None, description=None, url=None).query.filter_by(id=id).first()
    return send_file(
        file.url,file.name, as_attachment=True
    )

with app.app_context():
    db.create_all()
    

if __name__ == "__main__":
    app.run(port=5000, debug=True)