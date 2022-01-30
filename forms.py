import wtforms.validators
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Length
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class UserRegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=500)])
    last_name = StringField('Last Name', validators=[Length(max=500)])
    email = EmailField('Email', validators=[DataRequired(), Length(max=100), wtforms.validators.Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=100)])
    submit_registration = SubmitField('Register')


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Length(max=100), wtforms.validators.Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=100)])
    submit_login = SubmitField('Login')


class CommentForm(FlaskForm):
    comment_body = CKEditorField('Comment', validators=[Length(max=5000)])
    submit_comment = SubmitField('Add Comment')
