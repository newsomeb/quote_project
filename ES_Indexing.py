from datetime import datetime
from elasticsearch import Elasticsearch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Quote, Collection  # Import the models
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Function to create Elasticsearch index
def create_es_index(es_client, index_name, index_mappings):
    es_client.indices.create(index=index_name, body=index_mappings, ignore=400)


# Function to index quotes
def index_quotes(es_client, session):
    quotes_data = session.query(
        Quote.id, Quote.quote, Quote.author, Quote.summary
    ).all()

    for quote_id, quote_text, author, summary in quotes_data:
        try:
            doc = {
                'quote': quote_text,
                'author': author,
                'summary': summary,
                'suggest': {
                    'input': [quote_text, author, summary]  # Including summary for autocomplete
                }
            }
            es_client.index(index='quotes', id=quote_id, document=doc)
            print(f"Indexed quote ID {quote_id}")
        except Exception as e:
            print(f"Error indexing quote ID {quote_id}: {e}")


# Function to index collections
def index_collections(es_client, session):
    collections_data = session.query(Collection).all()

    for collection in collections_data:
        try:
            collection_doc = {
                'name': collection.name,
                'description': collection.description,
                'public': collection.public
                # Add other fields as necessary
            }
            es_client.index(index='collections', id=collection.id, document=collection_doc)
            print(f"Indexed collection ID {collection.id}")
        except Exception as e:
            print(f"Error indexing collection ID {collection.id}: {e}")


def main():
    # Elasticsearch client configuration
    es_client = Elasticsearch(
        "https://localhost:9200",
        basic_auth=("elastic", "J0*lP_fjAlRJx9dL0EOk"),
        verify_certs=False
    )

    # Define index mappings for quotes
    quote_index_mappings = {
        "settings": { ... },  # Add your settings (analysis etc.)
        "mappings": {
            "properties": {
                "quote": {"type": "text"},
                "author": {"type": "keyword"},
                "summary": {"type": "text"},
                "suggest": {"type": "completion"}  # For autocomplete
            }
        }
    }

    # Define index mappings for collections
    collection_index_mappings = {
        "settings": { ... },  # Add your settings
        "mappings": {
            "properties": {
                "name": {"type": "text"},
                "description": {"type": "text"},
                "public": {"type": "boolean"}  # Boolean field for public/private
            }
        }
    }

    # Create Elasticsearch indices
    create_es_index(es_client, 'quotes', quote_index_mappings)
    create_es_index(es_client, 'collections', collection_index_mappings)

    # Database connection and session management
    DATABASE_URI = 'sqlite:////home/tripleyeti/quote_project/create_quote_db_clean_data/quotes_cleaned.db'
    engine = create_engine(DATABASE_URI)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Index quotes and collections
    index_quotes(es_client, session)
    index_collections(es_client, session)

    # Close the session
    session.close()


if __name__ == "__main__":
    main()
