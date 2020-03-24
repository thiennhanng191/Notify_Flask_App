from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, time, timezone
from . import main
from .. import db
from ..models import User, Note
from flask_login import UserMixin, AnonymousUserMixin, login_user, LoginManager, current_user, login_required, logout_user

from tzlocal import get_localzone
import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

import simplejson as json

from pytz import timezone
import pytz

SCOPES = ['https://www.googleapis.com/auth/calendar']

@main.route('/', methods=['POST','GET'])
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
            return redirect(url_for('.index'))
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


@main.route('/delete/<int:id>')
@login_required
def delete(id):
    note_to_delete = Note.query.get_or_404(id)

    try:
        db.session.delete(note_to_delete)
        db.session.commit()
        flash('Note has been deleted')
        return redirect(url_for('.index'))
    except:
        return "There has been a problem deleting the note"

@main.route('/update/<int:id>', methods=['GET','POST'])
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
        return redirect(url_for('.index'))
    except:
        return "There was an issue updating your note"
    #else:
    #    return redirect('/')

@main.route('/new-event/', methods=['GET', 'POST'])
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
'''

@main.route('/register/', methods=['GET', 'POST'])
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


@main.route('/login/', methods=['GET', 'POST'])
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

@main.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    if os.path.exists("token.pickle"):
        os.remove("token.pickle")
    logout_user()
    flash('You have been logged out. See you again soon.')
    return redirect('/')


@main.route('/reset/', methods=['GET', 'POST'])
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

@main.route('/reset/<token>', methods=['GET', 'POST'])
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
'''
