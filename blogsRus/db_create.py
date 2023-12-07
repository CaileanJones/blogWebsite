from config import SQLALCHEMY_DATABASE_URI
from app import db, app
import os.path

with app.app_context():
    db.create_all()