from app import db
from flask_login import UserMixin

class Users(db.Model, UserMixin):
    userID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30))
    passHash = db.Column(db.String(80))

    def get_id(self):
           return (self.userID)

class Blogs(db.Model):
    blogID = db.Column(db.Integer, primary_key=True)
    userID = db.Column(db.Integer)
    timestamp = db.Column(db.Integer)
    title = db.Column(db.String(30))
    description = db.Column(db.String(30))
    content = db.Column(db.String(30))
    imgLink = db.Column(db.String(90))

class TagsLinker(db.Model):
    linkID = db.Column(db.Integer, primary_key=True)
    blogID = db.Column(db.Integer)
    tagID = db.Column(db.Integer)

class Tags(db.Model):
    tagID = db.Column(db.Integer, primary_key=True)
    tagName = db.Column(db.String(30))
