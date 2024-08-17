import sqlite3
import os


db_path = 'C:/Users/alexn/OneDrive/Desktop/quote_project/create_quote_db_clean_data/quotes_cleaned.db'
conn = sqlite3.connect(db_path)


cur = conn.cursor()


cur.execute('SELECT id, image_url FROM quotes_cleaned')
rows = cur.fetchall()


for row in rows:
    if row[1]: 
        id_ = row[0]  
        full_path = row[1]

       
        filename = os.path.basename(full_path)

      
        cur.execute('UPDATE quotes_cleaned SET image_url = ? WHERE id = ?', (filename, id_))
    else:
        print(f"No image_url for id {row[0]}")


conn.commit()
conn.close()
