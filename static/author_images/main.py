import os
import requests
import sqlite3
import time

BASE_URL = "https://en.wikipedia.org/w/api.php"
IMAGE_SAVE_DIR = r"C:\Users\alexn\OneDrive\Desktop\quote_project\author_images"

HEADERS = {
    'User-Agent': 'QuoteWebsiteScraper/1.0 (alexnewsome6@gmail.com; Website coming soon)'  # Replace with your details
}

# Ensure the directory exists
if not os.path.exists(IMAGE_SAVE_DIR):
    os.makedirs(IMAGE_SAVE_DIR)

def fetch_authors_from_db(db_path):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT author FROM quotes_cleaned")
        authors = cursor.fetchall()
    return [author[0] for author in authors]


def get_author_image_url(author_name):
    # Search for the author's page
    search_params = {
        "action": "query",
        "format": "json",
        "list": "search",
        "srsearch": author_name
    }
    response = requests.get(BASE_URL, params=search_params, headers=HEADERS)
    search_data = response.json()
    search_results = search_data.get("query", {}).get("search", [])

    # If no search results, return None
    if not search_results:
        return None

    # Use the title of the first search result to get the page image
    page_title = search_results[0].get("title", "")
    page_params = {
        "action": "query",
        "format": "json",
        "titles": page_title,
        "prop": "pageimages",
        "pithumbsize": 300  # Adjust size as needed
    }
    response = requests.get(BASE_URL, params=page_params, headers=HEADERS)
    page_data = response.json()

    pages = page_data.get("query", {}).get("pages", {})
    for _, page_content in pages.items():
        return page_content.get("thumbnail", {}).get("source", None)

    return None


def download_image(url, filename):
    response = requests.get(url, headers=HEADERS)
    with open(filename, 'wb') as f:
        f.write(response.content)

def main():
    db_path = r"C:\Users\alexn\OneDrive\Desktop\quote_project\create_quote_db_clean_data\quotes_cleaned.db"


    authors = fetch_authors_from_db(db_path)
    for author in authors:
        image_url = get_author_image_url(author)
        if image_url:
            image_filename = os.path.join(IMAGE_SAVE_DIR, f"{author}.jpg")
            download_image(image_url, image_filename)
            print(f"Downloaded image for {author} at {image_filename}")

            # Optional: If you want to update the database with the path:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE quotes_cleaned SET image_url = ? WHERE author = ?", (image_filename, author))
                conn.commit()
        else:
            print(f"No image found for {author}")

        time.sleep(2)  # Sleep for 2 seconds between each request

if __name__ == "__main__":
    main()
