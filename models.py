from extensions import db
from sqlalchemy import ForeignKey, Integer, Column, String, Date, Text
from sqlalchemy.orm import relationship


# Many-to-many table for Quote and Collection
quote_collection = db.Table('quote_collection',
    Column('quote_id', Integer, ForeignKey('quotes_cleaned.id'), primary_key=True),
    Column('collection_id', Integer, ForeignKey('collection.id'), primary_key=True)
)

class Quote(db.Model):
    __tablename__ = 'quotes_cleaned'
    id = Column(Integer, primary_key=True)
    quote = Column(String(1024), nullable=False)
    author = Column(String(128), nullable=False)
    birthday = Column(Date, nullable=True)
    deathday = Column(Date, nullable=True)
    summary = Column(String(2048), nullable=True)
    openai_generated_content = Column(Text)
    collections = relationship('Collection', secondary=quote_collection, backref='quotes')
    image_url = db.Column(db.String)

class Collection(db.Model):
    __tablename__ = 'collection'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(500))
    public = db.Column(db.Boolean)
    user = db.relationship('User', back_populates='collections')

    # Remove owner_id and owner relationship

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    _is_active = db.Column(db.Boolean, default=True, nullable=False)
    collections = db.relationship('Collection', back_populates='user')
    lockout_until = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    email_confirmed = db.Column(db.Boolean, default=False)


    # Relationship fields
    def get_owned_collections(self):
        return self.user_collections.all()

    @property
    def is_active(self):
        return self._is_active

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)
