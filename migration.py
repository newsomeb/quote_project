from flask import Flask
from extensions import db  e
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/alexn/OneDrive/Desktop/quote_project/create_quote_db_clean_data/quotes_cleaned.db'


db.init_app(app)


from models import Quote, Collection, User  


migrate = Migrate(app, db)

if __name__ == "__main__":
    app.run()
