import os
from flask import jsonify
from sqlalchemy import extract, func
import openai
from models import Quote
from wtforms import ValidationError
from datetime import timedelta
from quote_collections.routes import collections_bp
from wtforms.validators import EqualTo
from flask import render_template
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask import current_app
from extensions import db
from dotenv import load_dotenv
from models import User, Collection
from wtforms.validators import Length
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from wtforms import PasswordField, BooleanField
from wtforms.validators import Email
from os.path import basename
from sqlalchemy import text
from wtforms import validators
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import requests
from flask import request, flash, redirect, url_for, session
from datetime import datetime
import pytz
from elasticsearch import Elasticsearch
import logging
import urllib3
import random
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField
from flask import Flask
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask import request, flash, redirect, url_for, render_template
import requests
import json


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


load_dotenv()


bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
BASE_URL = 'thequotearchive.com'


limiter = Limiter(key_func=get_remote_address, default_limits=["10 per minute"])




def create_app():
    """
    Implements the create_app functionality.
    """

    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key')

    # ReCAPTCHA configuration
    app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')
    app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
    app.config['GOOGLE_CLOUD_PROJECT_ID'] = os.environ.get('GOOGLE_CLOUD_PROJECT_ID')

    # use this for connecting to production database
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/tripleyeti/quote_project/create_quote_db_clean_data/quotes_cleaned.db'

    # use this for local testing
    #app.config[
        #'SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/alexn/Desktop/quotes_cleaned.db'

    # Elasticsearch Configuration FOR LOCAL TESTING
    # Elasticsearch Configuration
    #es_host = 'http://localhost:9200'
    #es_username = 'elasticsearch'  # Replace with your Elasticsearch username
    #es_password = 'J0*lP_fjAlRJx9dL0EOk'  # Replace with your Elasticsearch password

    #app.es = Elasticsearch(
        #[es_host],
        #http_auth=(es_username, es_password)
    #)

    csrf = CSRFProtect(app)

    # Elasticsearch Configuration FOR PRODUCTION
    es_host = os.environ.get('ES_HOST', 'http://167.71.169.219:9200')

    es_username = os.environ.get('ES_USERNAME')
    es_password = os.environ.get('ES_PASSWORD')

    app.es = Elasticsearch(
        [es_host],
        http_auth=(es_username, es_password),
        verify_certs=False
    )
    db.init_app(app)


    app.config['MAILGUN_API_KEY'] = os.environ.get('MAILGUN_API_KEY')
    app.config['MAILGUN_DOMAIN'] = os.environ.get('MAILGUN_DOMAIN')

    app.config['CHATGPT_API_KEY'] = os.environ.get('CHATGPT_API_KEY')
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)






    logging.basicConfig(filename='app.log', level=logging.DEBUG)  # Log to a file

    app.send_file_max_age_default = timedelta(hours=1)
    cache = Cache(app, config={'CACHE_TYPE': 'simple'})

    mail = Mail(app)
    limiter.init_app(app)


    # Other initializations
    bcrypt.init_app(app)

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

    return app, s


app, s = create_app()


@app.errorhandler(429)
def ratelimit_error(e):
    """
    Implements the ratelimit_error functionality.
    """

    return jsonify(success=False, error="ratelimit exceeded %s" % e.description), 429


class MyForm(FlaskForm):
    """
    Defines the MyForm class.
    """

    my_field = StringField('My Field', [validators.Length(min=1, max=100)])

@app.route('/set_timezone', methods=['POST'])
def set_timezone():
    timezone = request.json.get('timezone')
    session['user_timezone'] = timezone
    return '', 200

# Dictionary mapping each month to a list of keywords for themes
seasonal_keywords = {
    'January': ['new year', 'resolution', 'beginning'],
    'February': ['love', 'valentine', 'affection'],
    'March': ['spring', 'growth', 'renewal'],
    'April': ['rain', 'blossom', 'fresh'],
    'May': ['flowers', 'mother', 'growth'],
    'June': ['sun', 'father', 'bright'],
    'July': ['independence', 'summer', 'celebration'],
    'August': ['heat', 'vacation', 'relaxation'],
    'September': ['school', 'learning', 'autumn'],
    'October': ['fall', 'halloween', 'harvest'],
    'November': ['thanksgiving', 'gratitude', 'family'],
    'December': ['holiday', 'winter', 'celebrate']
}

used_quote_ids = set()  # A set to keep track of already used quote IDs
def get_monthly_keywords(date):
    # Dictionary mapping each month to a list of keywords for themes
    seasonal_keywords = {
        1: ['new year', 'resolution', 'beginning'],
        2: ['love', 'valentine', 'affection'],
        3: ['spring', 'growth', 'renewal'],
        4: ['rain', 'blossom', 'fresh'],
        5: ['flowers', 'mother', 'growth'],
        6: ['sun', 'father', 'bright'],
        7: ['independence', 'summer', 'celebration'],
        8: ['heat', 'vacation', 'relaxation'],
        9: ['school', 'learning', 'autumn'],
        10: ['fall', 'halloween', 'harvest'],
        11: ['thanksgiving', 'gratitude', 'family'],
        12: ['holiday', 'winter', 'celebrate']
    }

    month = date.month
    return seasonal_keywords.get(month, [])


class CollectionForm(FlaskForm):
    name = StringField('Collection Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Create')

@app.route('/')
@app.route('/<int:year>/<int:month>/<int:day>')
def home(year=None, month=None, day=None):
    """
    Implements the home functionality, displaying quotes related to authors' birthdays
    and a random 'Quote of the Day' from a special collection.
    """
    # Timezone handling
    user_timezone = session.get('user_timezone', 'UTC')
    timezone = pytz.timezone(user_timezone)
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    local_now = utc_now.astimezone(timezone)


    # Determine the date for birthday quotes
    today = local_now.date() if year is None or month is None or day is None else datetime(year, month, day).date()

    form = CollectionForm()
    # Fetch birthday quotes for the day
    authors_birthday_today = (
        db.session.query(Quote)
        .with_entities(Quote.author, func.strftime('%Y-%m-%d', Quote.birthday),
                       func.strftime('%Y-%m-%d', Quote.deathday), Quote.image_url)
        .filter(extract('month', Quote.birthday) == today.month,
                extract('day', Quote.birthday) == today.day)
        .distinct()
        .limit(3)
        .all()
    )



    # Prepare data for the template
    birthday_quotes_data = []
    for author, birthday, deathday, author_image_url in authors_birthday_today:
        # Attempt to parse the birthday and deathday if not None and is a string
        try:
            birthday_parsed = datetime.strptime(birthday, '%Y-%m-%d') if birthday else None
            deathday_parsed = datetime.strptime(deathday, '%Y-%m-%d') if deathday else None
        except ValueError as e:
            print(f"Error parsing date for author {author}: {e}")
            birthday_parsed = None
            deathday_parsed = None

        quote = Quote.query.filter_by(author=author).order_by(func.random()).first()
        birthday_quotes_data.append({
            'quote': quote,
            'birthday': birthday_parsed,
            'deathday': deathday_parsed,
            'author_image_url': author_image_url,
        })

    # Calculate yesterday and tomorrow dates
    yesterday = today - timedelta(days=1)
    tomorrow = today + timedelta(days=1)

    # Fetch 'Quote of the Day' from the special collection
    quote_of_the_day_collection = Collection.query.filter_by(name="Quote of the Day").first()
    if quote_of_the_day_collection:
        day_seed = datetime.now().strftime("%Y%m%d")
        random.seed(day_seed)
        quotes = quote_of_the_day_collection.quotes
        quote_of_the_day = random.choice(quotes) if quotes else None
    else:
        quote_of_the_day = None

    # Render the template with the prepared data
    return render_template(
        'index.html',
        quotes_data=birthday_quotes_data,
        current_date=today,
        yesterday=yesterday,
        tomorrow=tomorrow,
        is_today=today == local_now.date(),
        quote_of_the_day=quote_of_the_day,
        form=form,
        quote = quote,
    )

@app.route('/authors/', methods=['GET', 'POST'])
def authors():
    """
    Implements the authors functionality.
    """

    query = request.args.get('query', "")
    if query:
        matched_authors = [result[0] for result in Quote.query.with_entities(Quote.author).filter(Quote.author.ilike(f"%{query}%")).distinct().all()]
        selected_authors_with_quotes = {}  # Empty dictionary for this case
    else:
        matched_authors = []
        selected_authors = [result[0] for result in Quote.query.with_entities(Quote.author).order_by(func.random()).distinct().limit(10).all()]

        # Fetching a quote for each selected author
        selected_authors_with_quotes = {
            author: Quote.query.filter_by(author=author).order_by(func.random()).first().quote
            for author in selected_authors
        }

    return render_template('authors.html', authors=matched_authors, selected_authors_with_quotes=selected_authors_with_quotes, query=query)




class UpdateAccountForm(FlaskForm):
    """
    Defines the UpdateAccountForm class.
    """

    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')




@app.route('/authors/<letter>/')
def authors_by_letter(letter):
    """
    Implements the authors_by_letter functionality.
    """

    last_name_initial = Quote.author.ilike(f'% {letter}%')
    authors = Quote.query.with_entities(Quote.author).filter(last_name_initial).distinct().all()
    return render_template('authors_by_letter.html', authors=authors)


@app.route('/quotes/<author>')
def author_quotes(author):
    """
    Implements the author_quotes functionality.
    """

    page = request.args.get('page', 1, type=int)
    pagination = Quote.query.filter_by(author=author).paginate(page=page, per_page=20)
    quotes = pagination.items

    # Adapt data structure for the template
    quotes_data = [{'quote': quote} for quote in quotes]

    form = CollectionForm()

    # Assuming you have a way to access the current user's collections.
    # If not, you'll need to adjust this part.
    # For users not logged in, you should handle it appropriately, possibly by setting collections to None or [].
    try:
        collections = current_user.collections
    except AttributeError:
        collections = []  # Or handle appropriately for non-logged-in users

    # Fetch the author's image URL directly from the first quote (assuming they are the same for all quotes by the author)
    author_image_url = quotes[0].image_url if quotes else None

    return render_template(
        'author_quotes.html',
        quotes_data=quotes_data,
        author=author,
        author_image_url=author_image_url,
        pagination=pagination,
        form=form,  # Pass the form object here
        current_user_collections=collections  # Assuming 'collections' is defined in your route
    )

@app.route('/search', methods=['GET', 'POST'])
def search():
    """
    Implements the search functionality.
    """

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
    """
    Implements the get_more_info functionality.
    """

    quote_text = request.json.get('quote')
    author_name = request.json.get('author_name', "an unknown author")
    info = generate_openai_content(quote_text, author_name)
    return jsonify({'info': info})


def generate_openai_content(quote_text, author_name="an unknown author"):
    """
    Implements the generate_openai_content functionality.
    """

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
    """
    Implements the logout functionality.
    """

    logout_user()
    return redirect(url_for('home'))


@app.route('/quote/<int:quote_id>')
def quote_display(quote_id):
    """
    Implements the quote_display functionality.
    """

    quote = Quote.query.get_or_404(quote_id)
    quote.openai_generated_content = generate_openai_content(quote.quote, quote.author)
    return render_template('quote_display.html', quote=quote)

@app.route('/topics')
def topics():
    """
    Implements the topics functionality.
    """

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



class LoginForm(FlaskForm):
    """
    Defines the LoginForm class.
    """

    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')



def validate_password_match(form, field):
    """
    Implements the validate_password_match functionality.
    """

    if field.data != form.password.data:
        raise ValidationError('Passwords must match.')



class RegistrationForm(FlaskForm):
    """
    Defines the RegistrationForm class.
    """

    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')
    email = StringField('Email', validators=[DataRequired(), Email()])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), validate_password_match])


@login_manager.user_loader
def load_user(user_id):
    """
    Implements the load_user functionality.
    """

    return db.session.query(User).get(int(user_id))


@app.route('/')
def index():
    """
    Implements the index functionality.
    """

    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Implements the dashboard functionality.
    """

    return render_template('dashboard.html', username=current_user.username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Implements the login functionality.
    """

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if not user:
            flash('No account found with that username.', 'login_error')
            return render_template('login.html', title='Login', form=form)

        if user.lockout_until and datetime.utcnow() < user.lockout_until:
            flash('Account locked due to multiple failed login attempts. Try again later.', 'login_error')
            return redirect(url_for('login'))

        if not user.email_confirmed:
            flash('Please confirm your email before logging in.', 'login_error')
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
            flash('Login unsuccessful. Please check username and password.', 'login_error')

    return render_template('login.html', title='Login', form=form)




def send_simple_message(to, subject, text):
    """
    Implements the send_simple_message functionality.
    """

    return requests.post(
        f"https://api.mailgun.net/v3/{app.config['MAILGUN_DOMAIN']}/messages",
        auth=("api", app.config['MAILGUN_API_KEY']),
        data={
            "from": "The Quote Archive Team <noreply@thequotearchive.com>",
            "to": [to],
            "subject": subject,
            "text": text
        }
    )



@app.route('/confirm-email-prompt')
def confirm_email_prompt():
    """
    Implements the confirm_email_prompt functionality.
    """

    return render_template('confirm_email_prompt.html')



# Inside your register route
@app.route("/register", methods=['GET', 'POST'])
def register():
    """
    Implements the register functionality.
    """
    form = RegistrationForm()

    if form.validate_on_submit():
        recaptcha_token = request.form.get('g-recaptcha-response')
        logging.debug(f"Received reCAPTCHA token: {recaptcha_token}")

        if not recaptcha_token or not verify_recaptcha(recaptcha_token, 'register'):
            logging.debug("reCAPTCHA validation failed.")
            flash('reCAPTCHA validation failed. Please try again.', 'danger')
            return render_template('register.html', form=form)

        # Check if username or email already exists
        user_exists = User.query.filter_by(username=form.username.data).first()
        email_exists = User.query.filter_by(email=form.email.data).first()

        logging.debug(f"User exists: {user_exists}, Email exists: {email_exists}")

        if user_exists:
            logging.debug("Username already taken.")
            flash('Username already taken. Please choose another one.', 'danger')
            return render_template('register.html', form=form)

        if email_exists:
            logging.debug("Email already in use.")
            flash('Email already in use. Please use a different email or login.', 'danger')
            return render_template('register.html', form=form)

        # Hash password and create new user instance
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)

        try:
            # Add new user to the database
            db.session.add(new_user)
            db.session.commit()

            logging.debug("User registration successful.")

            # Generate email confirmation token and send email
            token = s.dumps(new_user.email, salt='email-confirmation')
            confirmation_link = url_for('confirm_email', token=token, _external=True)
            send_confirmation_email(new_user.email, confirmation_link)

            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('confirm_email_prompt'))

        except Exception as e:
            # Rollback in case of any error
            db.session.rollback()
            logging.error(f"Registration failed due to an unexpected error: {e}")
            flash(f"Registration failed due to an unexpected error: {e}", 'danger')

    return render_template('register.html', form=form)


def verify_recaptcha(token, action):
    """
    Verifies the reCAPTCHA token with Google's reCAPTCHA Enterprise service.
    """
    logging.debug(f"Verifying reCAPTCHA token with action: {action}")

    payload = {
        'event': {
            'token': token,
            'siteKey': current_app.config['RECAPTCHA_SITE_KEY'],
            'expectedAction': action
        }
    }

    logging.debug(f"Sending reCAPTCHA verification payload: {payload}")  # Log payload

    response = requests.post(
        f'https://recaptchaenterprise.googleapis.com/v1/projects/{current_app.config["GOOGLE_CLOUD_PROJECT_ID"]}/assessments?key={current_app.config["RECAPTCHA_SECRET_KEY"]}',
        json=payload
    )

    result = response.json()
    logging.debug(f"Received reCAPTCHA verification response: {result}")  # Log response

    # Verify the token's validity and the risk analysis score
    isValid = result.get('tokenProperties', {}).get('valid', False)
    score = result.get('riskAnalysis', {}).get('score', 0)
    logging.debug(f"reCAPTCHA token valid: {isValid}, score: {score}")  # Log token validity and score

    return isValid and score >= 0.5
@app.errorhandler(404)
def page_not_found(e):
    """
    Implements the page_not_found functionality.
    """

    return render_template('404.html'), 404


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """
    Implements the account functionality.
    """

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
    """
    Defines the ChangePasswordForm class.
    """

    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Change Password')




@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    Implements the change_password functionality.
    """

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
    """
    Defines the DeleteAccountForm class.
    """

    submit = SubmitField('Delete Account')


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    """
    Implements the delete_account functionality.
    """

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
    """
    Implements the not_found_error functionality.
    """

    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """
    Implements the internal_error functionality.
    """

    db.session.rollback()  # If you're using a database, it's good to rollback any changes in case of errors
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    """
    Implements the forbidden_error functionality.
    """

    return render_template('403.html'), 403


@app.route('/confirm_email/<token>')
def confirm_email(token):
    """
    Implements the confirm_email functionality.
    """

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

        # Log the user in after confirming their email
        login_user(user)

    return redirect(url_for('login'))


def send_confirmation_email(email, token):
    """
    Implements the send_confirmation_email functionality.
    """

    confirmation_link = token  # Just use the token directly

    return requests.post(
        f"https://api.mailgun.net/v3/{app.config['MAILGUN_DOMAIN']}/messages",
        auth=("api", app.config['MAILGUN_API_KEY']),
        data={
            "from": "The Quote Archive Team <noreply@thequotearchive.com>",
            "to": [email],
            "subject": "Email Confirmation",
            "text": f"Please click the following link to confirm your email: {confirmation_link}"
        }
    )

@app.route('/es_search', methods=['GET'])
def es_search():
    query = request.args.get('query', default="", type=str)
    page = request.args.get('page', 1, type=int)
    PER_PAGE = 10
    offset = (page - 1) * PER_PAGE

    # Construct an advanced Elasticsearch query
    query_body = {
        "query": {
            "bool": {
                "should": [
                    {"match": {"author": {"query": query, "boost": 5}}},
                    {"match": {"quote": {"query": query, "boost": 1}}},
                    {"match": {"summary": {"query": query, "boost": 1}}}
                ],
                "minimum_should_match": 1
            }
        }
    }

    # Elasticsearch search query
    response = app.es.search(index='quotes', body=query_body, size=PER_PAGE, from_=offset)

    # Process the search results
    matching_quotes = [
        {
            'quote': hit['_source']['quote'],
            'author': hit['_source']['author'],
            'image_url': hit['_source'].get('image_url'),
            'id': hit['_id']
        } for hit in response['hits']['hits']
    ]

    total_quotes = response['hits']['total']['value']
    total_pages = (total_quotes + PER_PAGE - 1) // PER_PAGE

    # Simple pagination object with a custom iter_pages method
    class Pagination:
        def __init__(self, page, total_pages, display_pages=5):
            self.page = page
            self.total_pages = total_pages
            self.display_pages = display_pages

        def iter_pages(self):
            left_edge = 2  # Always show first 2 pages
            right_edge = 2  # Always show last 2 pages
            left_current = 2  # Number of pages to show to the left of the current page
            right_current = 2  # Number of pages to show to the right of the current page
            last = 0

            for num in range(1, self.total_pages + 1):
                if num <= left_edge or \
                        (self.page - left_current <= num <= self.page + right_current) or \
                        num > self.total_pages - right_edge:
                    if last + 1 != num:
                        yield None  # Insert ellipsis
                    yield num
                    last = num

    pagination = Pagination(page, total_pages)

    return render_template(
        'search_results_es.html',
        quotes=matching_quotes,
        query=query,
        page=page,
        pagination=pagination,
        total_pages=total_pages
    )


@app.route('/test/es_data', methods=['GET'])
def test_es_data():
    # Safely retrieve the Elasticsearch client
    es_client = getattr(current_app, 'es', None)
    if not es_client:
        # Handle the error appropriately if es_client is not available
        return jsonify(error="Elasticsearch client not initialized"), 500

    response = es_client.search(index="quotes", query={"match_all": {}}, size=10)
    documents = [hit["_source"] for hit in response['hits']['hits']]
    return jsonify(documents)

@app.route('/autocomplete', methods=['GET'])
def autocomplete():
    query = request.args.get('query', '')
    suggest_body = {
        "suggest": {
            "quote-suggest": {
                "prefix": query,
                "completion": {
                    "field": "suggest"
                }
            }
        }
    }
    response = app.es.search(index='quotes', body=suggest_body)
    suggestions = [option['_source'] for option in response['suggest']['quote-suggest'][0]['options']]
    return jsonify(suggestions)

@app.route('/collections_search', methods=['GET'])
def collections_search():
    query = request.args.get('query', default="", type=str)
    page = request.args.get('page', 1, type=int)
    PER_PAGE = 10
    offset = (page - 1) * PER_PAGE

    # Elasticsearch query for collections
    query_body = {
        "query": {
            "multi_match": {
                "query": query,
                "fields": ["name", "description"]
            }
        },
        "from": offset,
        "size": PER_PAGE
    }

    response = app.es.search(index='collections', body=query_body)

    # Process search results
    matching_collections = [
        {
            'name': hit['_source']['name'],
            'description': hit['_source'].get('description'),
            'id': hit['_id']
        } for hit in response['hits']['hits']
    ]

    total_collections = response['hits']['total']['value']
    total_pages = (total_collections + PER_PAGE - 1) // PER_PAGE

    # Simple pagination object with a custom iter_pages method
    class Pagination:
        def __init__(self, page, total_pages):
            self.page = page
            self.total_pages = total_pages

        def iter_pages(self):
            return range(1, self.total_pages + 1)

    pagination = Pagination(page, total_pages)

    return render_template(
        'collections_search_results.html',
        collections=matching_collections,
        query=query,
        page=page,
        pagination=pagination,
        total_pages=total_pages
    )



@app.route('/quote/<int:quote_id>')
def quote_page(quote_id):
    # Retrieve the quote based on quote_id from the database
    quote = Quote.query.get_or_404(quote_id)

    # Optionally, fetch the author's image URL if needed
    author_image_url = quote.image_url if quote.image_url else None

    # Render the template with the retrieved quote and author's image URL
    return render_template('quote_page.html', quote=quote, author_image_url=author_image_url)


@app.route('/quote_detail/<int:quote_id>')
def quote_detail(quote_id):
    quote = Quote.query.get_or_404(quote_id)

    # Optionally, fetch the author's image URL if needed
    author_image_url = quote.image_url if quote.image_url else None

    # Render the template with the retrieved quote and author's image URL
    return render_template('quote_page.html', quote=quote, author_image_url=author_image_url)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
