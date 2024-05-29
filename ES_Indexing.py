import time
import logging
from elasticsearch import Elasticsearch, helpers
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from models import Quote, Collection
import urllib3
from transformers import BertTokenizer, BertModel
import torch
import os

# Set up logging to file with a maximum file size
log_filename = 'es_indexing.log'
if os.path.isfile(log_filename):
    if os.path.getsize(log_filename) > 10 * 1024 * 1024:  # 10 MB max size
        os.remove(log_filename)

logging.basicConfig(filename=log_filename,
                    filemode='a',  # Append mode, so logs are added to the file
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)  # Set the logging level

logging.info("Starting the Elasticsearch indexing process")

# Disable urllib3 warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load pre-trained BERT tokenizer and model
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
model = BertModel.from_pretrained('bert-base-uncased')


def get_bert_embeddings(text):
    inputs = tokenizer(text, return_tensors='pt', padding=True, truncation=True)
    outputs = model(**inputs)
    embeddings = outputs.last_hidden_state.mean(dim=1)  # Take the mean of the token embeddings
    return embeddings.detach().numpy().flatten()  # Ensure embeddings are a flat array


# Define index mappings with custom analyzers
quote_index_mappings = {
    "settings": {
        "analysis": {
            "analyzer": {
                "custom_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "asciifolding", "synonym", "stop", "stemmer"]
                }
            },
            "filter": {
                "synonym": {
                    "type": "synonym",
                    "synonyms": [
                        "motivational, inspiring"
                    ]
                },
                "stop": {
                    "type": "stop",
                    "stopwords": "_english_"
                },
                "stemmer": {
                    "type": "stemmer",
                    "language": "english"
                }
            }
        }
    },
    "mappings": {
        "properties": {
            "quote": {"type": "text", "analyzer": "custom_analyzer"},
            "author": {"type": "text"},
            "summary": {"type": "text"},
            "suggest": {"type": "completion"},
            "embeddings": {"type": "dense_vector", "dims": 768}  # BERT embeddings dimension
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


# Function to create Elasticsearch index
def create_es_index(es_client, index_name, index_mappings):
    try:
        if not es_client.indices.exists(index=index_name):
            es_client.indices.create(index=index_name, body=index_mappings)
            logging.info(f"Created Elasticsearch index: {index_name}")
    except Exception as e:
        logging.error(f"Error creating Elasticsearch index {index_name}: {e}")


# Function to index quotes in batches with BERT embeddings
def index_quotes(es_client, session, batch_size=100):
    try:
        total_quotes = session.query(func.count(Quote.id)).scalar()
        for offset in range(0, total_quotes, batch_size):
            batch = session.query(
                Quote.id, Quote.quote, Quote.author, Quote.summary
            ).order_by(Quote.id).limit(batch_size).offset(offset).all()

            actions = []
            for quote in batch:
                text = f"{quote.quote} {quote.author} {quote.summary}"
                embeddings = get_bert_embeddings(text).flatten()
                logging.info(f"Indexing quote ID {quote.id} with embeddings: {embeddings}")

                action = {
                    "_index": "quotes",
                    "_id": quote.id,
                    "_source": {
                        'quote': quote.quote,
                        'author': quote.author,
                        'summary': quote.summary,
                        'suggest': {
                            'input': list(filter(None, [quote.quote, quote.author, quote.summary]))
                        },
                        'embeddings': embeddings.tolist()  # Convert to list for JSON serialization
                    }
                }
                actions.append(action)

            try:
                success, failed = helpers.bulk(es_client, actions, raise_on_error=False, stats_only=False)
                logging.info(f"Indexed quotes batch: {offset}-{offset + batch_size}")

                # Log details of failed documents
                if failed:
                    for fail in failed:
                        logging.error(f"Failed to index document ID {fail['index']['_id']}: {fail['index']['error']}")
            except Exception as e:
                logging.error(f"Error indexing batch from {offset} to {offset + batch_size}: {e}")
    except Exception as e:
        logging.error(f"Error during bulk indexing: {e}")


# Function to index collections in batches
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

            try:
                helpers.bulk(es_client, actions)
                logging.info(f"Indexed collections batch: {offset}-{offset + batch_size}")
            except Exception as e:
                logging.error(f"Error indexing batch from {offset} to {offset + batch_size}: {e}")
    except Exception as e:
        logging.error(f"Error during bulk indexing: {e}")


def main():
    try:
        # Elasticsearch client configuration
        # PRODUCTION
        es_client = Elasticsearch(
            ["http://167.71.169.219:9200"],
            http_auth=("elastic", "Pooppoop"),
            verify_certs=False
        )

        # Create Elasticsearch indices
        create_es_index(es_client, 'quotes', quote_index_mappings)
        create_es_index(es_client, 'collections', collection_index_mappings)

        # Database connection and session management
        DATABASE_URI = 'sqlite:////home/tripleyeti/quote_project/create_quote_db_clean_data/quotes_cleaned.db'
        engine = create_engine(DATABASE_URI)
        Session = sessionmaker(bind=engine)
        session = Session()

        # Index data in batches
        index_quotes(es_client, session)
        index_collections(es_client, session)

        session.close()

    except Exception as e:
        logging.error(f"Error in main function: {e}")


if __name__ == "__main__":
    main()