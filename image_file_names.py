import sqlite3
import os

# Connect to your database
db_path = 'C:/Users/alexn/OneDrive/Desktop/quote_project/create_quote_db_clean_data/quotes_cleaned.db'
conn = sqlite3.connect(db_path)

# Create a cursor object using the connection
cur = conn.cursor()

# Assuming your table name is `quotes_cleaned` and the columns are `id` and `image_url`
cur.execute('SELECT id, image_url FROM quotes_cleaned')
rows = cur.fetchall()

# Loop over the rows and update each one
for row in rows:
    if row[1]:  # Check if the image_url is not None
        id_ = row[0]  # Renamed to avoid conflict with Python's built-in id
        full_path = row[1]

        # Extract filename from the full path
        filename = os.path.basename(full_path)

        # Update the record with the filename
        cur.execute('UPDATE quotes_cleaned SET image_url = ? WHERE id = ?', (filename, id_))
    else:
        print(f"No image_url for id {row[0]}")

# Commit the changes and close the connection
conn.commit()
conn.close()
