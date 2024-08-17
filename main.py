import os
from sqlalchemy import extract, func
import openai
from wtforms import ValidationError
from datetime import timedelta
from quote_collections.routes import collections_bp
from wtforms.validators import EqualTo
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from extensions import db
from dotenv import load_dotenv
from models import User, Collection, Quote
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
from datetime import datetime
import pytz
from elasticsearch import Elasticsearch
import logging
import urllib3
import random
from wtforms import TextAreaField
from wtforms.validators import DataRequired
from flask import flash, redirect, url_for, render_template
import requests
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from transformers import BertModel, BertTokenizer
import torch
from flask import Flask
import time
from flask import current_app
from flask_wtf.csrf import generate_csrf
from flask_wtf.csrf import CSRFProtect



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


load_dotenv()


bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
BASE_URL = 'thequotearchive.com'


limiter = Limiter(key_func=get_remote_address, default_limits=["10 per minute"])
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
model = BertModel.from_pretrained('bert-base-uncased')


def create_app():
    app = Flask(__name__)

    # Set a default secret key if one is not provided in the environment
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-default-secret-key-here'

    csrf = CSRFProtect(app)

    @app.after_request
    def add_csrf_token_to_response(response):
        response.set_cookie('csrf_token', generate_csrf())
        return response

    # ReCAPTCHA configuration
    app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')
    app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
    app.config['GOOGLE_CLOUD_PROJECT_ID'] = os.environ.get('GOOGLE_CLOUD_PROJECT_ID')
    app.config['YOUR_SECRET_KEY'] = os.environ.get('YOUR_SECRET_KEY')

    # use this for connecting to production database
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/tripleyeti/quote_project/create_quote_db_clean_data/quotes_cleaned.db'

    # use this for local testing
    #app.config[
        #'SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/alexn/Desktop/quotes_cleaned.db'

    # use this for local testing on MAC!
    #app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/puter/Desktop/quotes_cleaned.db'

    # Elasticsearch Configuration FOR LOCAL TESTING
    # Elasticsearch Configuration
    #es_host = 'http://localhost:9200'
    #es_username = 'elasticsearch'  # Replace with your Elasticsearch username
    #es_password = 'J0*lP_fjAlRJx9dL0EOk'  # Replace with your Elasticsearch password

    #app.es = Elasticsearch(
        #[es_host],
        #http_auth=(es_username, es_password)
    #)



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

    admin = Admin(app, name='MyApp Admin', template_mode='bootstrap3')

    class AdminModelView(ModelView):
        def is_accessible(self):
            # Define your logic for admin accessibility
            return current_user.is_authenticated and current_user.is_admin

        def inaccessible_callback(self, name, **kwargs):
            # Define what to do if a user tries to access a protected view
            flash('You do not have permission to access the admin dashboard.', 'danger')
            return redirect(url_for('login'))

    # Customize admin views for specific models
    class UserAdmin(AdminModelView):
        column_searchable_list = ('username', 'email')



    class QuoteAdmin(AdminModelView):
        column_searchable_list = ('quote', 'author')
        page_size = 100

    class CollectionAdmin(AdminModelView):
        column_searchable_list = ('name',)

    admin.add_view(AdminModelView(User, db.session, category='Data Management'))

    admin.add_view(QuoteAdmin(Quote, db.session, category='Data Management'))
    admin.add_view(CollectionAdmin(Collection, db.session, category='Data Management'))

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

    return app, s, csrf


app, s, csrf = create_app()




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
    # Manually set the user timezone
    user_timezone = 'America/New_York'  # Replace with your correct timezone
    timezone = pytz.timezone(user_timezone)
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    local_now = utc_now.astimezone(timezone)

    # Determine the date for birthday quotes
    if year is None or month is None or day is None:
        today = local_now.date()
    else:
        today = datetime(year, month, day, tzinfo=timezone).date()

    form = CollectionForm()

    # Fetch birthday quotes for the day, prioritizing those with context
    authors_birthday_today = (
        db.session.query(Quote)
        .with_entities(Quote.author, func.strftime('%Y-%m-%d', Quote.birthday),
                       func.strftime('%Y-%m-%d', Quote.deathday), Quote.image_url)
        .filter(extract('month', Quote.birthday) == today.month,
                extract('day', Quote.birthday) == today.day)
        .order_by(case((Quote.context != None, literal(0)), else_=literal(1)), Quote.id)
        .distinct()
        .limit(3)
        .all()
    )

    # Prepare data for the template
    birthday_quotes_data = []
    for author, birthday, deathday, author_image_url in authors_birthday_today:
        try:
            birthday_parsed = datetime.strptime(birthday, '%Y-%m-%d') if birthday else None
            deathday_parsed = datetime.strptime(deathday, '%Y-%m-%d') if deathday else None
        except ValueError as e:
            birthday_parsed = None
            deathday_parsed = None

        quote = Quote.query.filter_by(author=author).order_by(Quote.id).first()
        birthday_quotes_data.append({
            'quote': quote,
            'birthday': birthday_parsed,
            'deathday': deathday_parsed,
            'author_image_url': author_image_url,
        })

    yesterday = today - timedelta(days=1)
    tomorrow = today + timedelta(days=1)

    quote_of_the_day_collection = Collection.query.filter_by(name="Quote of the Day").first()
    if quote_of_the_day_collection:
        day_seed = today.strftime("%Y%m%d")
        random.seed(day_seed)
        quotes = quote_of_the_day_collection.quotes
        quote_of_the_day = random.choice(quotes) if quotes else None
    else:
        quote_of_the_day = None

    return render_template(
        'index.html',
        quotes_data=birthday_quotes_data,
        current_date=today,
        yesterday=yesterday,
        tomorrow=tomorrow,
        is_today=today == local_now.date(),
        quote_of_the_day=quote_of_the_day,
        form=form,
    )


@app.route('/authors/', methods=['GET', 'POST'])
def authors():
    """
    Implements the authors functionality by searching for authors.
    """
    query = request.args.get('query', "")
    if query:
        # Fetch authors matching the query
        matched_authors = [result[0] for result in Quote.query.with_entities(Quote.author).filter(Quote.author.ilike(f"%{query}%")).distinct().all()]
    else:
        matched_authors = []

    # No need to fetch quotes here as we're focusing on matching authors
    return render_template('authors.html', authors=matched_authors, query=query)



class UpdateAccountForm(FlaskForm):
    """
    Defines the UpdateAccountForm class.
    """

    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')





from sqlalchemy import case, literal
from sqlalchemy import case, literal
from sqlalchemy import case, literal
import re
from sqlalchemy import case, literal
import re


@app.route('/quotes/<author>')
def author_quotes(author):
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Keep your current per_page value

    # Create a case statement for ordering using the new syntax
    order_case = case(
        (Quote.context != None, literal(0)),
        else_=literal(1)
    )

    # Query with ordering and pagination
    pagination = Quote.query.filter_by(author=author) \
        .order_by(order_case, Quote.id) \
        .paginate(page=page, per_page=per_page, error_out=False)

    quotes = pagination.items

    quotes_data = []
    for quote in quotes:
        quote_data = {
            'quote': quote,
            'id': quote.id,
            'author': quote.author,
            'book_title': quote.book_title,
            'has_valid_context': False
        }
        if quote.context:
            quote_data['has_valid_context'] = True  # If there's a context, consider it valid
        quotes_data.append(quote_data)
        print(f"Quote ID: {quote.id}, Has context: {quote_data['has_valid_context']}, Context: {quote.context[:50] if quote.context else 'None'}...")

    form = CollectionForm()

    try:
        collections = current_user.collections
    except AttributeError:
        collections = []

    author_image_url = quotes[0].image_url if quotes else None

    return render_template(
        'author_quotes.html',
        quotes_data=quotes_data,
        author=author,
        author_image_url=author_image_url,
        pagination=pagination,
        form=form,
        current_user_collections=collections
    )



class SearchForm(FlaskForm):
    query = StringField('Search')
    submit = SubmitField('Go')

@app.route('/search', methods=['GET', 'POST'])
def search():
    """
    Implements the search functionality.
    """
    form = SearchForm(request.args)
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
                           total_quotes=total_quotes, total_pages=total_pages, form=form)

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
        # Check if username or email already exists
        user_exists = User.query.filter_by(username=form.username.data).first()
        email_exists = User.query.filter_by(email=form.email.data).first()
        if user_exists:
            flash('Username already taken. Please choose another one.', 'danger')
            return render_template('register.html', form=form)
        if email_exists:
            flash('Email already in use. Please use a different email or login.', 'danger')
            return render_template('register.html', form=form)

        # Hash password and create new user instance
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)

        # Add new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Create a default Favorites collection for the new user
        favorites_collection = Collection(name="Favorites", user_id=new_user.id, is_favorite=True)
        db.session.add(favorites_collection)
        db.session.commit()

        # Generate email confirmation token and send email
        token = s.dumps(new_user.email, salt='email-confirmation')
        confirmation_link = url_for('confirm_email', token=token, _external=True, _scheme='https')
        send_confirmation_email(new_user.email, confirmation_link)

        flash('Registration successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('confirm_email_prompt'))

    return render_template('register.html', form=form)


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
    min_relevance_score = 5.0  # Adjust this value to filter out more irrelevant results

    search_form = SearchForm()

    # Elasticsearch query to find authors matching the query
    author_query_body = {
        "query": {
            "match": {
                "author": {
                    "query": query,
                    "fuzziness": "AUTO"
                }
            }
        }
    }

    # Search for authors
    author_response = app.es.search(index='quotes', body=author_query_body, size=5)
    matching_authors = {hit['_source']['author'] for hit in author_response['hits']['hits']}

    # Elasticsearch query for quotes by the author
    author_quotes_query_body = {
        "query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "author": {
                                "query": query,
                                "fuzziness": "AUTO"
                            }
                        }
                    }
                ],
                "should": [
                    {"match_phrase": {"author": query}},
                    {"term": {"author": query}}
                ],
                "minimum_should_match": 1
            }
        },
        "min_score": min_relevance_score
    }

    # Search for quotes by the author
    author_quotes_response = app.es.search(index='quotes', body=author_quotes_query_body, size=PER_PAGE, from_=offset)
    author_quotes = [
        {
            'quote': hit['_source']['quote'],
            'author': hit['_source']['author'],
            'image_url': hit['_source'].get('image_url'),
            'id': hit['_id']
        } for hit in author_quotes_response['hits']['hits']
    ]

    # Elasticsearch query for related quotes
    related_query_body = {
        "query": {
            "bool": {
                "must": [
                    {
                        "multi_match": {
                            "query": query,
                            "fields": ["quote^5", "author^2"],
                            "fuzziness": "AUTO"
                        }
                    }
                ],
                "should": [
                    {"match_phrase": {"quote": query}},
                    {"term": {"author": query}}
                ],
                "minimum_should_match": 1
            }
        },
        "min_score": min_relevance_score
    }

    # Search for related quotes
    related_response = app.es.search(index='quotes', body=related_query_body, size=PER_PAGE, from_=offset)
    related_quotes = [
        {
            'quote': hit['_source']['quote'],
            'author': hit['_source']['author'],
            'image_url': hit['_source'].get('image_url'),
            'id': hit['_id']
        } for hit in related_response['hits']['hits']
    ]

    total_quotes = related_response['hits']['total']['value']
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
                        (self.page - left_current <= num and num <= self.page + right_current) or \
                        num > self.total_pages - right_edge:
                    if last + 1 != num:
                        yield None  # Insert ellipsis
                    yield num
                    last = num

    pagination = Pagination(page, total_pages)

    collection_form = CollectionForm()

    return render_template(
        'search_results_es.html',
        matching_authors=matching_authors,
        author_quotes=author_quotes,
        quotes=related_quotes,
        query=query,
        page=page,
        pagination=pagination,
        total_pages=total_pages,
        search_form=search_form,  # Add this line
        collection_form=collection_form
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

def get_bert_embeddings(text):
    """
    Generate BERT embeddings for a given text.
    :param text: Input text for which to generate embeddings
    :return: BERT embeddings as a numpy array
    """
    inputs = tokenizer(text, return_tensors='pt', truncation=True, padding=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
    embeddings = outputs.last_hidden_state.mean(dim=1).squeeze().numpy()
    return embeddings


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

    # Instantiate the form
    form = CollectionForm()

    # Render the template with the retrieved quote and author's image URL
    return render_template('quote_page.html', quote=quote, author_image_url=author_image_url, form=form)

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')

@app.route('/submitquote')
def submitquote():
    return render_template('submitquote.html')

@app.route('/privacypolicy')
def privacypolicy():
    return render_template('privacypolicy.html')


@app.context_processor
def inject_footer_content():
    # Topics for the footer
    footer_topics = random.sample([
        "Romance", "Heartbreak", "Loyalty", "Trust", "Drive", "Determination",
        "Optimism", "Hopefulness", "Faith", "Learning"
    ], 5)  # Select 5 random topics

    # Authors and a sample quote for the footer
    authors_quotes = {
        "MLK Jr": "The time is always right to do what is right.",
        "Tolstoy": "Everyone thinks of changing the world, but no one thinks of changing himself.",
        "Joan Didion": "We tell ourselves stories in order to live.",
        "Leonardo DiCaprio": "If you can do what you do best and be happy, you're further along in life than most people.",
        "Jane Austen": "There is no charm equal to tenderness of heart."
    }
    footer_authors = random.sample(list(authors_quotes.items()), 3)  # Select 3 random authors

    return dict(footer_topics=footer_topics, footer_authors=footer_authors)



from flask import send_from_directory

@app.route('/sitemap_index.xml')
def sitemap_index():
    # Serves the sitemap index file from the static/sitemaps directory
    return send_from_directory('static/sitemaps', 'sitemap_index.xml')

@app.route('/sitemap<number>.xml')
def sitemap(number):
    # Serves individual sitemap files from the static/sitemaps directory
    # Make sure to capture the `number` parameter correctly in the route
    return send_from_directory('static/sitemaps', f'sitemap{number}.xml')


from fuzzywuzzy import fuzz
import re





from flask import jsonify, request
from fuzzywuzzy import fuzz
import re
@app.route('/check_context/<int:quote_id>', methods=['GET'])
def check_context(quote_id):
    try:
        quote = Quote.query.get(quote_id)
        if quote and quote.context:
            match = match_quote_in_context(quote.quote, quote.context)
            return jsonify({"has_valid_context": match is not None}), 200
        return jsonify({"has_valid_context": False}), 200
    except Exception as e:
        app.logger.error(f"Error in check_context: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500
def normalize_text(text):
    return re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', '', text)).strip().lower()


from flask import session
import secrets


@app.before_request
def create_session_token():
    if 'token' not in session or request.endpoint == 'match_quote':
        session['token'] = secrets.token_hex(16)
        session['token_created_at'] = time.time()

    app.logger.info(f"Current session token: {session.get('token')}")


@app.route('/match_quote', methods=['POST'])
@csrf.exempt
def match_quote():


    try:
        data = request.get_json()


        if not data:
            current_app.logger.error("No JSON data received")
            return jsonify(error="No JSON data received"), 400

        quote = data.get('quote')
        context = data.get('context')

        if not quote or not context:
            current_app.logger.error("Missing quote or context")
            return jsonify(error="Missing quote or context"), 400

        match = match_quote_in_context(quote, context)
        if match:
            current_app.logger.info(f"Match found: {match}")
            return jsonify(match)
        else:
            current_app.logger.warning("Quote not found in context")
            return jsonify(error="Quote not found in context"), 404

    except Exception as e:
        current_app.logger.exception(f"An unexpected error occurred: {str(e)}")
        return jsonify(error=f"An unexpected error occurred: {str(e)}"), 500

# Exempt the route after defining it
csrf.exempt(match_quote)


def match_quote_in_context(quote, context):


    # Remove extra whitespace and quotes from the quote
    clean_quote = re.sub(r'\s+', ' ', quote.strip().strip('"'))

    best_ratio = 0
    best_match = None

    # Split the context into sentences
    sentences = re.split(r'(?<=[.!?])\s+', context)

    for sentence in sentences:
        ratio = fuzz.partial_ratio(clean_quote.lower(), sentence.lower())
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = sentence

    if best_ratio > 90:  # Adjust this threshold as needed

        start_index = context.index(best_match)
        end_index = start_index + len(best_match)
        return {
            'before': context[:start_index],
            'quote': best_match,
            'after': context[end_index:],
            'match_quality': best_ratio
        }
    else:

        # Return the full context as 'after' and include the best_match
        return {
            'before': '',
            'quote': best_match if best_match else '',
            'after': context,
            'match_quality': best_ratio
        }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)

