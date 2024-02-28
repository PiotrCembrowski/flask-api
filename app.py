from flask import Flask
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:postgres@localhost:5432/postgres"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Files(db.Model):
    __tablename__ = 'files'

    id = db.Column(db.Integer, primary_key=True)


api = Api(app)

files = [
    {   
        'id':'1',
        'name':'First file',
        'description': 'File about something',
        'created_at': '1990/03/23',
    },
    {
        'id':'2',
        'name':'Second file',
        'description': 'Second about something',
        'created_at': '1990/03/23',
    },
    {
        'id':'3',
        'name':'Third file',
        'description': 'Third about something',
        'created_at': '1990/03/23',
    },
]

class Files(Resource):
    def get(self,name):
        for file in files:
           if file['name'] == name:
               return file
           
        return {'name':None}, 404

    def post(self,name):
        
        file = {'name':name}

        files.append(file)

        return file

    def delete(self,name):
        for ind,file in enumerate(files):
            if file['name'] == name:
                deleted_file = files.pop(ind)
                print(deleted_file)
                return {'note':'delete success'}
            
class AllFiles(Resource):

    def get(self):
        return {'files':files}



api.add_resource(Files, '/file/<string:name>')
api.add_resource(AllFiles, '/files')

if __name__ == '__main__':
    app.run(debug=True)