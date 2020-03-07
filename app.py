from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
import flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, time, timezone
from tzlocal import get_localzone
import time
#from auth.forms import RegistrationForm, LoginForm, PasswordResetRequestForm, PasswordResetForm
import os
from flask_bootstrap import Bootstrap
#from models import User
from flask_login import UserMixin, AnonymousUserMixin, login_user, LoginManager, current_user, login_required, logout_user

import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, url_for

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError

from sqlalchemy.sql import column
from sqlalchemy import Column

#from email_sending import send_email
from flask_mail import Mail, Message
from threading import Thread
#from emails import configure_mail, send_email


import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

import simplejson as json

from pytz import timezone
import pytz
# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/calendar']

app = Flask(__name__)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

db = SQLAlchemy(app)

app.config.update(dict(
    DEBUG = True,
    MAIL_DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = os.environ.get('NOTIFY_MAIL_USERNAME'),
    MAIL_PASSWORD = os.environ.get('NOTIFY_MAIL_PASSWORD'),
))
mail = Mail(app)
mail.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Note(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable=False)
    content = db.Column(db.String(200),nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return '<Note %r>' %self.id

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    posts = db.relationship('Note', backref='owner', lazy='dynamic')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id}).decode('utf-8')

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def __repr__(self):
        return '<User %r>' %self.id


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username',
                            validators=[DataRequired(),
                            Length(1, 64),
                            Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                            'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password',
                            validators=[DataRequired(),
                                        EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Email already register. Please try logging in')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    submit = SubmitField('Reset Password')

class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')



@app.route('/', methods=['POST','GET'])
@login_required
def index():
    user = current_user._get_current_object()
    if request.method == 'POST':
        note_title = request.form["note-title"]
        note_content = request.form["note-content"]
        new_note = Note(title=note_title, content=note_content, owner_id=user.id)

        try:
            db.session.add(new_note)
            db.session.commit()
            return redirect('/')
        except:
            return 'There was a problem adding your note. Please try again!'
    else:
        #id = current_user.get_id()
        #user = User.query.get(1)
        #user = current_user._get_current_object()
        #if (not isintance(user, User)):
        #    flash('checkpoint')
        notes = Note.query.filter_by(owner_id=user.id).order_by(Note.date_created).all()
        #if (update.has_been_called):
        #    note = Note.query.get_or_404(cur_note_id)
        #else:
        #update_id = int(request.args.get('id'))
        return render_template('render_notes.html', notes = notes, user=user)
        #return render_template('layout.html', user=user)


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    note_to_delete = Note.query.get_or_404(id)

    try:
        db.session.delete(note_to_delete)
        db.session.commit()
        flash('Note has been deleted')
        return redirect('/')
    except:
        return "There has been a problem deleting the note"

@app.route('/update/<int:id>', methods=['GET','POST'])
@login_required
def update(id):
    note_to_update = Note.query.get_or_404(id)
    #update.has_been_called = True
    #global cur_note_id
    #cur_note_id = note_to_update.id

    #if request.method == 'POST':
    #note_to_update.id = id
    note_to_update.title = request.form["note-title"]
    note_to_update.content = request.form["note-content"]
    try:
        db.session.commit()
        return redirect('/')
    except:
        return "There was an issue updating your note"
    #else:
    #    return redirect('/')


@app.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data.lower(),
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        #send_email(user.email, 'Confirm Your Account',
        #           'auth/email/confirm', user=user, token=token)
        #flash('A confirmsation email has been sent to you by email.')
        return redirect('/')
    return render_template('register.html', form=form)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)

            #return render_template('layout.html', user=user)
            #redirect('/')
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('index')
            return redirect(next)
        flash('Invalid email or password')
    return render_template('login.html', form=form)

@app.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    if os.path.exists("token.pickle"):
        os.remove("token.pickle")
    logout_user()
    flash('You have been logged out. See you again soon.')
    return redirect('/')


@app.route('/reset/', methods=['GET', 'POST'])
def password_reset_request():
    #if not current_user.is_anonymous:
    #    return redirect('/')
    flash('Please provide an email address where you want to receive instructions to reset your password')
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       "auth/reset_password",
                       user=user, token=token)
        flash('An email with instructions to reset your password has been '
              'sent to you.')
        return redirect(url_for('login'))
    #return('checkpoint')
    return render_template('reset_password.html', form=form)

@app.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    #if not current_user.is_anonymous:
    #    return redirect('/')
    form = PasswordResetForm()
    if form.validate_on_submit():
        if User.reset_password(token, form.password.data):
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('login'))
        else:
            return redirect('/')
    user = current_user._get_current_object()
    return render_template('reset_password.html', form=form)

def datetime_handler(x):
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")

@app.route('/new-event/', methods=['GET', 'POST'])
def add_event():
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('calendar', 'v3', credentials=creds)

    tz = get_localzone()

    event_name = request.form["event-name"]
    event_description = request.form["event-description"]
    event_location = request.form["event-location"]
    start_date = request.form["event-startdate"]
    start_time = request.form["event-starttime"]
    start_time+=':00'
    #start_datetime = start_date + "T" + start_time
    start_datetime_str = start_date + 'T'+ start_time
    start_datetime = datetime.strptime(start_datetime_str, '%Y-%m-%dT%H:%M:%S')
    start_datetime_local = tz.localize(start_datetime, is_dst=None)
    start_datetime_tz = start_datetime_local.astimezone(pytz.utc)

    #start_datetime_tz = start_datetime.replace(tzinfo=pytz.UTC).astimezone(tz=None)
    #start_datetime_tz.isoformat()
    end_date = request.form["event-enddate"]
    end_time = request.form["event-endtime"]
    end_time+=':00'
    #end_datetime = end_date + "T" + end_time
    end_datetime_str = end_date + 'T' + end_time
    end_datetime = datetime.strptime(end_datetime_str, '%Y-%m-%dT%H:%M:%S')
    end_datetime_local = tz.localize(end_datetime, is_dst=None)
    end_datetime_tz = end_datetime_local.astimezone(pytz.utc)
    #end_datetime_tz = end_datetime.replace(tzinfo=pytz.UTC).astimezone(tz=None)
    #end_datetime_tz.isoformat()

    event = {
        'summary': event_name,
        'location': event_location,
        'description': event_description,
        'start': {
            'dateTime': start_datetime_tz.isoformat(),
            #'timeZone': 'America/Los_Angeles',
        },
        'end': {
            'dateTime': end_datetime_tz.isoformat(),
            #'timeZone': 'America/Los_Angeles',
        },
        'reminders': {
            'useDefault': False,
            'overrides': [
              {'method': 'email', 'minutes': 24 * 60},
              {'method': 'popup', 'minutes': 10},
            ],
          },
    }
    event = service.events().insert(calendarId='primary', body=event).execute()
    flash('Event has been created on your Google Calendar')
    #flash('Event has created: %s' % (event.get('htmlLink')))
    return redirect('/')



@app.template_filter('date_format')
def custom_date(date):
    date = datetime.strptime(str(date), '%Y-%m-%d')
    return date.strftime('%b %d, %Y')


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    msg = Message('Notify' + ' ' + subject,
                  sender='Notify Admin <thiennhannguyen191@gmail.com>', recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()


if __name__ == "__main__":
    db.create_all()
    #configure_mail(app)
    #app.run(debug = True)
    mail = Mail(app)
    app.run(debug = True, host='0.0.0.0')
