from sqlalchemy import create_engine, MetaData
from sqlalchemy.engine.reflection import Inspector

DATABASE_URI = 'sqlite:////Users/alexn/OneDrive/Desktop/quote_project/create_quote_db_clean_data/quotes_cleaned.db'  # replace this with your actual database URI

engine = create_engine(DATABASE_URI)
metadata = MetaData()

# Reflect database
metadata.reflect(bind=engine)

inspector = Inspector.from_engine(engine)

# Get table information
print("Tables")
print("-" * 40)
for table_name in inspector.get_table_names():
    print("Table:", table_name)
    print("Columns:", inspector.get_columns(table_name))
    print("Foreign Keys:", inspector.get_foreign_keys(table_name))
    print("-" * 40)
