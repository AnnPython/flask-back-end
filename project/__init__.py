from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_restplus import Api


from config import Config


app = Flask(__name__)
app.config.from_object(Config)

authorizations = {
    "apikey": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-KEY",
        "description": "Type in the *Value'* input box below: **'Bearer &lt;JWT&gt;'**, where JWT is the token"
    },
}

api = Api(app, default="CRUD", default_label="Managing shop operations",
          security="apikey", authorizations=authorizations,
          version='1.0', title='Shoes shop', description='Don`t stop yourself')


db = SQLAlchemy(app)

ma = Marshmallow(app)
migrate = Migrate(app, db)

from project import routes
