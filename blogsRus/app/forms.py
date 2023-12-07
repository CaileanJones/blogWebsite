from flask_wtf import FlaskForm
from wtforms import validators, StringField, PasswordField, FileField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField(u'Username', validators=[DataRequired(), validators.length(max=20)])
    password = PasswordField(u'Password', validators=[DataRequired(), validators.length(max=50)])

class SignUpForm(FlaskForm):
    username = StringField(u'Username', validators=[DataRequired(), validators.length(max=20)])
    password = PasswordField('Password', validators=[DataRequired(), validators.length(max=50)])
    confirm  = PasswordField('Confirm Password', validators=[DataRequired(), validators.length(max=50)])

class SearchForm(FlaskForm):
    query = StringField(u'Search Query', validators=[validators.length(max=60)])

class CreatePostForm(FlaskForm):
    title = StringField(u'title', validators=[validators.length(max=20)])
    description = StringField(u'desc', validators=[validators.length(max=50)])
    content = StringField(u'content', validators=[validators.length(max=5000)])
    photo = FileField(u'photo')
