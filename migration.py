from flask import Flask
from extensions import db  # Assuming you have a separate extensions module
from flask_migrate import Migrate

# Initialize app and configure it
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/alexn/OneDrive/Desktop/quote_project/create_quote_db_clean_data/quotes_cleaned.db'

# Initialize extensions
db.init_app(app)

# Import your models after initializing your db extension
from models import Quote, Collection, User  # This ensures the models are aware of the db instance

# Integrate Flask-Migrate
migrate = Migrate(app, db)

if __name__ == "__main__":
    app.run()
