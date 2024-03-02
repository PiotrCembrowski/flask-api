from flask import Flask
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from flask import request

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:root@localhost:5432/sf"
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)

class FilesList(db.Model):
    __tablename__ = 'fileslist'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"<File {self.name}>"

@app.route('/files', methods=['POST', 'GET'])
def handle_files():
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

@app.route('/files/<name>', methods=['GET', 'PUT', 'DELETE'])
def handle_file(name):
    list = FilesList.query.get_or_404(name)

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

if __name__ == '__main__':
    app.run(debug=True)