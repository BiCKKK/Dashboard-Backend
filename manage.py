from flask import Flask
from flask_migrate import Migrate
from shared import db
from shared.models import *
from shared.config import Config

app = Flask(__name__)

app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)