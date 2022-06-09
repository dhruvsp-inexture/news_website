from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import current_user, login_required, login_user, logout_user
from news_website import db, bcrypt
from news_website.users.forms import LoginForm, RegistrationForm, PasswordResetForm, ResetPasswordForm
from news_website.models import User, userType
from news_website.users.utils import send_reset_email

users = Blueprint("users", __name__)


@users.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('main.home_page'))
    form = LoginForm()
    if form.validate_on_submit():
        # user = User.query.filter_by(email=form.email.data).first()
        # if user and (user.password == form.password.data):
        #     login_user(user)
        #     flash("Login Successful", 'success')
        #     return redirect(url_for('users.profile_page', user_id=current_user.id))
        # else:
        #     flash('Invalid email or password', 'danger')
        #     return redirect(url_for('users.login_page'))
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                flash('Login Successful', 'success')
                return redirect(url_for('main.home_page'))
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)


@users.route('/register', methods=['GET', 'POST'])
def registration_page():
    if current_user.is_authenticated:
        return redirect(url_for('main.home_page'))
    form = RegistrationForm()
    if form.validate_on_submit():
        ut = userType.query.filter_by(type=form.user_type.data).first()
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(user_type_id=ut.user_type_id, fname=form.fname.data, lname=form.lname.data, gender=form.gender.data,
                    email=form.email.data, phone=form.phone.data, age=form.age.data, address=form.address.data,
                    password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! Now you can login to your account', 'success')
        return redirect(url_for('users.login_page'))
    return render_template('registration.html', form=form)


@login_required
@users.route('/profile/<int:user_id>')
def profile_page(user_id):
    if user_id == current_user.id:
        typeOfUser = userType.query.filter_by(user_type_id=current_user.user_type_id).first()
        return render_template('profile.html', typeOfUser=typeOfUser)
    else:
        abort(403)


@users.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home_page'))


@users.route("/reset_password", methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent to your id please check it to reset your password.', 'info')
        return redirect(url_for('users.login_page'))
    return render_template('reset_password_request.html', form=form)


@users.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home_page'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('users.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You can now log in', 'success')
        return redirect(url_for('users.login_page'))
    return render_template('reset_token.html', form=form)
