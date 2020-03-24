from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, PasswordResetRequestForm, PasswordResetForm
import os
import os.path

@auth.route('/register/', methods=['GET', 'POST'])
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
        return redirect(url_for('main.index'))
    return render_template('register.html', form=form)


@auth.route('/login/', methods=['GET', 'POST'])
def login():
    #if current_user.is_authenticated:
    #    return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)

            #return render_template('layout.html', user=user)
            #redirect('/')
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid email or password')
    return render_template('login.html', form=form)

@auth.route('/logout/', methods=['GET', 'POST'])
@login_required
def logout():
    if os.path.exists("token.pickle"):
        os.remove("token.pickle")
    logout_user()
    flash('You have been logged out. See you again soon.')
    return redirect('/')


@auth.route('/reset/', methods=['GET', 'POST'])
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

@auth.route('/reset/<token>', methods=['GET', 'POST'])
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
