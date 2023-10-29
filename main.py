import os
from datetime import date
from flask import jsonify, request
from sqlalchemy import extract, func
import openai
from models import Quote
from wtforms import ValidationError
from datetime import datetime, timedelta
from quote_collections.routes import collections_bp
from wtforms.validators import EqualTo
from flask import Flask, render_template, redirect, flash, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask import session
from flask import current_app
from extensions import db
from dotenv import load_dotenv
from models import User
from wtforms.validators import Length
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from wtforms import PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email
from os.path import basename
from sqlalchemy import text
from flask_wtf import FlaskForm
from wtforms import StringField, validators
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import logging
import requests


load_dotenv()

# Instantiate extensions
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
BASE_URL = 'thinkexist.net'


limiter = Limiter(key_func=get_remote_address, default_limits=["10 per minute"])


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key')

    # use this for connecting to production database
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/tripleyeti/quote_project/create_quote_db_clean_data/quotes_cleaned.db'

    # use this for local testing
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/alexn/Desktop/quotes_cleaned.db'

    app.config['MAILGUN_API_KEY'] = os.environ.get('MAILGUN_API_KEY')
    app.config['MAILGUN_DOMAIN'] = os.environ.get('MAILGUN_DOMAIN')

    app.config['CHATGPT_API_KEY'] = os.environ.get('CHATGPT_API_KEY')
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)


    logging.basicConfig(filename='app.log', level=logging.DEBUG)  # Log to a file

    app.send_file_max_age_default = timedelta(hours=1)
    cache = Cache(app, config={'CACHE_TYPE': 'simple'})

    mail = Mail(app)
    limiter.init_app(app)


    # Other initializations...
    bcrypt.init_app(app)
    db.init_app(app)
    mail.init_app(app)

    # Initialize login manager
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    # Register blueprints
    app.register_blueprint(collections_bp)

    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    @app.template_filter('basename')
    def basename_filter(s):
        return basename(s)

    @app.errorhandler(429)
    def ratelimit_error(e):
        return jsonify(success=False, error="ratelimit exceeded %s" % e.description), 429

    return app, s  # if you need limiter outside create_app, otherwise just return app, s


app, s = create_app()  # if you need limiter outside create_app, otherwise just app, s = create_app()

@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify(success=False, error="ratelimit exceeded %s" % e.description), 429


class MyForm(FlaskForm):
    my_field = StringField('My Field', [validators.Length(min=1, max=100)])


@app.route('/')
@app.route('/<int:year>/<int:month>/<int:day>')
def home(year=None, month=None, day=None):
    # Set today's date to either provided date or current date
    today = date(year, month, day) if year and month and day else date.today()

    # Get authors with birthdays today, limit to 3 distinct authors
    authors_birthday_today = (
        Quote.query
        .with_entities(Quote.author, func.strftime('%Y-%m-%d', Quote.birthday),
                       func.strftime('%Y-%m-%d', Quote.deathday), Quote.image_url)
        .filter(extract('month', Quote.birthday) == today.month,
                extract('day', Quote.birthday) == today.day)
        .distinct()
        .limit(3)
        .all()
    )

    # Retrieve one quote per author and prepare data for the template
    birthday_quotes_data = [{
        'quote': Quote.query.filter_by(author=author).order_by(func.random()).first(),
        'birthday': datetime.strptime(birthday, '%Y-%m-%d') if birthday else None,
        'deathday': datetime.strptime(deathday, '%Y-%m-%d') if deathday else None,
        'author_image_url': author_image_url,
    } for author, birthday, deathday, author_image_url in authors_birthday_today if
        Quote.query.filter_by(author=author).first()]

    # Calculate yesterday and tomorrow dates relative to today
    yesterday = today - timedelta(days=1)
    tomorrow = today + timedelta(days=1)

    # Render the template with the prepared data
    return render_template(
        'index.html',
        quotes_data=birthday_quotes_data,
        current_date=today,
        yesterday=yesterday,
        tomorrow=tomorrow,
        is_today=today == date.today(),
    )





@app.route('/authors/', methods=['GET', 'POST'])
def authors():
    query = request.args.get('query', "")
    if query:
        # Use ilike for case-insensitive search
        matched_authors = [result[0] for result in Quote.query.with_entities(Quote.author).filter(Quote.author.ilike(f"%{query}%")).distinct().all()]
        selected_authors = []  # setting it to an empty list here
    else:
        matched_authors = []  # setting it to an empty list here
        selected_authors = [result[0] for result in Quote.query.with_entities(Quote.author).order_by(func.random()).distinct().limit(10).all()]

    return render_template('authors.html', authors=matched_authors, selected_authors=selected_authors, query=query)





class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')




@app.route('/authors/<letter>/')
def authors_by_letter(letter):
    last_name_initial = Quote.author.ilike(f'% {letter}%')
    authors = Quote.query.with_entities(Quote.author).filter(last_name_initial).distinct().all()
    return render_template('authors_by_letter.html', authors=authors)


@app.route('/quotes/<author>')
def author_quotes(author):
    page = request.args.get('page', 1, type=int)
    pagination = Quote.query.filter_by(author=author).paginate(page=page, per_page=20)
    quotes = pagination.items

    # Fetch the author's image URL directly from the first quote (assuming they are the same for all quotes by the author)
    if quotes:
        author_image_url = quotes[0].image_url
    else:
        author_image_url = None

    return render_template('author_quotes.html', quotes=quotes, author=author, author_image_url=author_image_url, pagination=pagination)


@app.route('/search', methods=['GET', 'POST'])
def search():
    query = request.args.get('query', default="", type=str)
    page = request.args.get('page', 1, type=int)
    PER_PAGE = 10
    offset = (page - 1) * PER_PAGE  # Calculate the offset

    with db.engine.connect() as connection:
        # Getting total count of matching quotes
        stmt_count = text("SELECT COUNT(*) FROM quotes_fts WHERE quotes_fts MATCH :query")
        total_quotes = connection.execute(stmt_count, {"query": query}).scalar()

        stmt = text("""
            SELECT quotes_fts.quote, quotes_fts.author, quotes_cleaned.image_url 
            FROM quotes_fts 
            JOIN quotes_cleaned ON quotes_fts.rowid = quotes_cleaned.id
            WHERE quotes_fts MATCH :query
            LIMIT :limit OFFSET :offset
        """)

        results = connection.execute(stmt, {"query": query, "limit": PER_PAGE, "offset": offset}).fetchall()


        matching_quotes = [{'quote': row[0], 'author': row[1], 'image_url': row[2]} for row in results]

    total_pages = (total_quotes + PER_PAGE - 1) // PER_PAGE  # Ceiling division

    return render_template('search_results.html', quotes=matching_quotes, query=query, page=page, per_page=PER_PAGE,
                           total_quotes=total_quotes, total_pages=total_pages)


@app.route('/get_more_info', methods=['POST'])
def get_more_info():
    quote_text = request.json.get('quote')
    author_name = request.json.get('author_name', "an unknown author")
    info = generate_openai_content(quote_text, author_name)
    return jsonify({'info': info})


def generate_openai_content(quote_text, author_name="an unknown author"):
    openai.api_key = current_app.config['CHATGPT_API_KEY']

    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user",
         "content": f"The quote, '{quote_text}', is said to be by {author_name}. Can information or context be provided without using the pronoun 'you'? Are there any popular interpretations or interesting facts related to it? Do not repeat the quote. Just go into your explanation"}
    ]

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages
        )
        response_content = response.choices[0].message['content'].strip()

        # Remove unnecessary details and long explanations
        response_content = response_content.split('.')  # Split by sentence
        response_content = '.'.join(response_content[:min(3, len(response_content))])  # Take the first 3 sentences

        # Group sentences into clusters for paragraphs
        paragraphs = ['<p>' + response_content + '</p>']
        response_content = ''.join(paragraphs)

        # If the model mentions uncertainty about the source or the quote’s validity:
        if "not certain" in response_content or "unknown" in response_content:
            response_content = "<p>Unfortunately, definitive context or background information for this quote is not available. For accurate and reliable information on this author’s works and thoughts, consider referring to authoritative resources or the author's published works.</p>"

        # Replace some first-person references if they appear
        response_content = response_content.replace("I'm ", "One is ").replace(" I ", " one ").replace("I've",
                                                                                                       "One has").replace(
            "I don't", "One doesn't")

        return response_content

    except Exception as e:
        print(f"OpenAI API error: {e}")
        return "An error occurred while fetching additional information."


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/quote/<int:quote_id>')
def quote_display(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    quote.openai_generated_content = generate_openai_content(quote.quote, quote.author)
    return render_template('quote_display.html', quote=quote)

@app.route('/topics')
def topics():
    popular_topics = [
        "Love",
        "Inspiration",
        "Success",
        "Happiness",
        "Friendship",
        "Motivational",
        "Positive",
        "Life",
        "Funny",
        "Beauty",
        "Hope",
        "God",
        "Nature",
        "Growth",
        "Challenges",
        "Family",
        "Wisdom",
        "Courage",
        "Dreams",
        "Change",
        "Leadership",
        "Time"
    ]

    half_length = len(popular_topics) // 2
    return render_template('topics.html', topics=popular_topics, half_length=half_length)


# Assuming the beginning of your main.py has already imported the necessary modules/packages.

# Remove the Blueprint instantiation since we won't be using it.
# account_bp = Blueprint('account', __name__)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')



def validate_password_match(form, field):
    if field.data != form.password.data:
        raise ValidationError('Passwords must match.')



class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')
    email = StringField('Email', validators=[DataRequired(), Email()])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), validate_password_match])


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if not user:
            flash('No account found with that username.', 'danger')
            return render_template('login.html', title='Login', form=form)

        if user.lockout_until and datetime.utcnow() < user.lockout_until:
            flash('Account locked due to multiple failed login attempts. Try again later.', 'danger')
            return redirect(url_for('login'))

        if not user.email_confirmed:
            flash('Please confirm your email before logging in.', 'warning')
            return redirect(url_for('login'))

        if bcrypt.check_password_hash(user.password, form.password.data):
            user.failed_login_attempts = 0  # reset on successful login
            login_user(user, remember=form.remember.data)
            session.permanent = True
            db.session.commit()
            return redirect(url_for('account'))
        else:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:  # adjust the threshold as needed
                user.lockout_until = datetime.utcnow() + timedelta(minutes=30)  # lockout for 30 minutes
            db.session.commit()
            flash('Login unsuccessful. Please check username and password.', 'danger')

    return render_template('login.html', title='Login', form=form)



def send_simple_message(to, subject, text):
    return requests.post(
        f"https://api.mailgun.net/v3/{app.config['MAILGUN_DOMAIN']}/messages",
        auth=("api", app.config['MAILGUN_API_KEY']),
        data={
            "from": "Think Exist <mailgun@thinkexist.net>",
            "to": [to],
            "subject": subject,
            "text": text
        }
    )



@app.route('/confirm-email-prompt')
def confirm_email_prompt():
    return render_template('confirm_email_prompt.html')



@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user_exists = User.query.filter_by(username=form.username.data).first()
        email_exists = User.query.filter_by(email=form.email.data).first()

        if user_exists:
            flash('Username already taken. Please choose another one.', 'danger')
            return render_template('register.html', form=form)
        if email_exists:
            flash('Email already in use. Please use a different email or login.', 'danger')
            return render_template('register.html', form=form)

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data)

        # Email confirmation
        token = s.dumps(new_user.email, salt='email-confirmation')
        confirmation_link = url_for('confirm_email', token=token, _external=True)

        try:
            db.session.add(new_user)
            db.session.commit()
            send_confirmation_email(new_user.email, confirmation_link)
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('confirm_email_prompt'))
        except Exception as e:
            db.session.rollback()
            flash(f"Registration failed due to an unexpected error: {e}", 'danger')
            return render_template('register.html', form=form)

    return render_template('register.html', form=form)




@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('account.html', form=form)




class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Change Password')




@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        # Check if the provided current password is correct
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('The current password is incorrect. Please try again.', 'danger')
            return redirect(url_for('change_password'))

        # Update the user's password
        current_user.password = generate_password_hash(form.new_password.data, method='sha256')
        db.session.commit()

        flash('Your password has been changed!', 'success')
        return redirect(url_for('account'))

    return render_template('change_password.html', form=form)

class DeleteAccountForm(FlaskForm):
    submit = SubmitField('Delete Account')


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    form = DeleteAccountForm()
    if form.validate_on_submit():
        user_id = current_user.id  # Get the id of the logged-in user
        logout_user()  # Log the user out

        # Fetch the actual user object using the user_id
        user_to_delete = db.session.query(User).get(int(user_id))


        if user_to_delete:  # Ensure the user exists
            db.session.delete(user_to_delete)  # Delete the user record
            db.session.commit()
            flash('Your account has been deleted!', 'success')
            return redirect(url_for('home'))  # Or wherever you want to redirect the user after deletion

    return render_template('delete_account.html', title='Delete Account', form=form)


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # If you're using a database, it's good to rollback any changes in case of errors
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403




@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirmation', max_age=3600)  # token valid for 1 hour
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if user.email_confirmed:
        flash('Email already confirmed.', 'success')
    else:
        user.email_confirmed = True
        db.session.commit()
        flash('Email confirmed!', 'success')

    return redirect(url_for('login'))


def send_confirmation_email(email, token):
    confirmation_link = url_for('confirm_email', token=token, _external=True)

    return requests.post(
        f"https://api.mailgun.net/v3/{app.config['MAILGUN_DOMAIN']}/messages",
        auth=("api", app.config['MAILGUN_API_KEY']),
        data={
            "from": "Think Exist <mailgun@thinkexist.net>",
            "to": [email],
            "subject": "Email Confirmation",
            "text": f"Please click the following link to confirm your email: {confirmation_link}"
        }
    )



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
