from flask import url_for
from flask_mail import Message
from news_website import mail


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message("Password Reset Request",
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''Click on the following link to reset your password:
{url_for('users.reset_token', token=token, _external=True)}
If you didn't send this password reset request then please ignore this mail'''

    mail.send(msg)
