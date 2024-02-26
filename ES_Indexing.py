import time
import logging
from elasticsearch import Elasticsearch, helpers
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from models import Quote, Collection
from elasticsearch.helpers import bulk

import logging

# Set up logging to file
logging.basicConfig(filename='es_indexing.log',
                    filemode='a',  # Append mode, so logs are added to the file
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)  # Set the logging level

# Test logging
logging.info("Starting the Elasticsearch indexing process")

# Disable urllib3 warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to create Elasticsearch index
def create_es_index(es_client, index_name, index_mappings):
    try:
        if not es_client.indices.exists(index=index_name):
            es_client.indices.create(index=index_name, body=index_mappings)
            logging.info(f"Created Elasticsearch index: {index_name}")
    except Exception as e:
        logging.error(f"Error creating Elasticsearch index {index_name}: {e}")

# Function to index quotes in batches
# Function to index quotes individually
# Function to index quotes individually with null value handling
def index_quotes(es_client, session, batch_size=100):
    try:
        total_quotes = session.query(func.count(Quote.id)).scalar()
        for offset in range(0, total_quotes, batch_size):
            batch = session.query(
                Quote.id, Quote.quote, Quote.author, Quote.summary
            ).order_by(Quote.id).limit(batch_size).offset(offset).all()

            for quote in batch:
                doc = {
                    'quote': quote.quote,
                    'author': quote.author,
                    'summary': quote.summary,
                    'suggest': {
                        'input': list(filter(None, [quote.quote, quote.author, quote.summary]))
                    }
                }

                try:
                    es_client.index(index='quotes', id=quote.id, document=doc)
                    logging.info(f"Indexed quote ID {quote.id}")
                except Exception as e:
                    logging.error(f"Error indexing quote ID {quote.id}: {e}")
    except Exception as e:
        logging.error(f"Error during bulk indexing: {e}")


# Function to index collections in batches with enhanced error logging
def index_collections(es_client, session, batch_size=100):
    try:
        total_collections = session.query(func.count(Collection.id)).scalar()
        for offset in range(0, total_collections, batch_size):
            batch = session.query(Collection).order_by(Collection.id).limit(batch_size).offset(offset).all()
            actions = [
                {
                    "_index": "collections",
                    "_id": collection.id,
                    "_source": {
                        'name': collection.name,
                        'description': collection.description,
                        'public': collection.public
                    }
                } for collection in batch
            ]

            resp = helpers.bulk(es_client, actions, stats_only=False)
            success, failed = resp[0], resp[1]

            # Log details of failed documents
            for failure in failed:
                logging.error(f"Bulk index failure for collection ID {failure['_id']}: {failure['error']}")

            logging.info(f"Indexed collections batch: {offset}-{offset+batch_size}. Success: {success}, Failed: {len(failed)}")
            time.sleep(1)
    except Exception as e:
        logging.error(f"Error indexing collections: {e}")

def main():
    try:
        # Elasticsearch client configuration
        # PRODUCTION
        # es_client = Elasticsearch(
        #    ["http://167.71.169.219:9200"],
        #    http_auth=("elastic", "Pooppoop"),
        #    verify_certs=False
        # )

        # LOCAL
        es_client = Elasticsearch(
            ["http://localhost:9200"],
            verify_certs=False
        )

        # Define index mappings
        # Define index mappings for quotes and collections (replace with your mappings)
        quote_index_mappings = {
            "mappings": {
                "properties": {
                    "quote": {"type": "text"},
                    "author": {"type": "text"},
                    "summary": {"type": "text"},
                    "suggest": {"type": "completion"}
                }
            }
        }

        collection_index_mappings = {
            "mappings": {
                "properties": {
                    "name": {"type": "text"},
                    "description": {"type": "text"},
                    "public": {"type": "boolean"}
                }
            }
        }

        # Database connection and session management
        # PRODUCTIONDATABASE_URI = 'sqlite:////home/tripleyeti/quote_project/create_quote_db_clean_data/quotes_cleaned.db'
        # LOCAL
        DATABASE_URI = 'sqlite:///C:/Users/alexn/Desktop/quotes_cleaned.db'
        engine = create_engine(DATABASE_URI)
        Session = sessionmaker(bind=engine)
        session = Session()

        # Create Elasticsearch indices
        create_es_index(es_client, 'quotes', quote_index_mappings)
        create_es_index(es_client, 'collections', collection_index_mappings)

        # Query for total quotes and collections
        total_quotes = session.query(func.count(Quote.id)).scalar()
        total_collections = session.query(func.count(Collection.id)).scalar()

        # Print the total counts
        print(f"Total Quotes: {total_quotes}")
        print(f"Total Collections: {total_collections}")

        # Index data in batches
        index_quotes(es_client, session)
        index_collections(es_client, session)

        session.close()

    except Exception as e:
        logging.error(f"Error in main function: {e}")

if __name__ == "__main__":
    main()

