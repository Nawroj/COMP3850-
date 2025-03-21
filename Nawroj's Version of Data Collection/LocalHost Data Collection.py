import requests
import json
import csv
import re
from datetime import datetime
import logging
import psycopg2  # Import the psycopg2 library

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_feed_data(feed_url):
    """Fetches data from a given URL."""
    try:
        response = requests.get(feed_url, timeout=100)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {feed_url}: {e}")
        return None

def parse_plain_text_feed(data, source_name):
    """Parses plain text feed data, ignoring lines starting with # and matching CIDR IP ranges."""
    if not data:
        return []
    lines = data.splitlines()
    results = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            # Match IP addresses or CIDR IP ranges
            ip_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?)$", line) #modified regex

            url_match = re.match(r"^(http|https)://", line)
            domain_match = re.search(r"([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}", line)
            hash_match = re.search(r"([a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})", line)

            if ip_match:
                results.append({'type': 'IP', 'value': ip_match.group(1), 'source': source_name, 'timestamp': datetime.now()})
            elif url_match:
                results.append({'type': 'URL', 'value': line, 'source': source_name, 'timestamp': datetime.now()})
            elif domain_match:
                results.append({'type': 'Domain', 'value': domain_match.group(0), 'source': source_name, 'timestamp': datetime.now()})
            elif hash_match:
                results.append({'type': 'Hash', 'value': hash_match.group(0), 'source': source_name, 'timestamp': datetime.now()})

    return results

def parse_json_feed(data, source_name):
    return []

def parse_csv_feed(data, source_name):
    """Parses CSV feed data, handling comma-separated values (IPs, Hashes, URLs) in a single line,
    and handling cases where the order of columns might be incorrect."""
    if not data:
        return []

    lines = data.splitlines()
    reader = csv.reader(line for line in lines if not line.strip().startswith('#'))  # Skip comment lines

    results = []
    for row in reader:
        try:
            if len(row) >= 3 and "Hash Feed" not in source_name and row[0] != "Date" and "# Banco do Brasil (MD5 Fingerprints)" not in row[0]: # added hash feed check and header check
                listing_date_str, values_str, listing_reason = row[:3] # take the first 3 columns.
                try:
                    listing_date = datetime.strptime(listing_date_str, "%Y-%m-%d")
                except ValueError:
                    # try to parse date in other format
                    try:
                        listing_date = datetime.strptime(listing_date_str, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                       #if date parsing still fails, try to see if the first column is a URL, if so, treat all columns as URLs.
                       if re.match(r"^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$", listing_date_str):
                           for value in row:
                               value = value.strip()
                               results.append({
                                'type': 'URL',
                                'value': value,
                                'source': source_name,
                                'timestamp': None, #timestamp is not available.
                                'listing_reason': None, #listing reason is not available.
                               })
                           continue #skip to the next row.
                       else:
                            logging.error(f"Error parsing date in {source_name}: {listing_date_str}, row:{row}")
                            continue

                values = values_str.split(',')  # Split comma-separated values

                for value in values:
                    value = value.strip()  # Remove leading/trailing whitespace

                    # Determine the type based on the value (IP, Hash, or URL)
                    if all(c.isdigit() or c == "." or c == "/" for c in value.replace("/", "").replace(".", "")):
                        indicator_type = 'IP'
                    elif re.match(r"^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$", value):
                        indicator_type = 'URL'
                    else:
                        indicator_type = 'Hash'  # default to hash if not IP or URL

                    results.append({
                        'type': indicator_type,
                        'value': value,
                        'source': source_name,
                        'timestamp': listing_date,
                        'listing_reason': listing_reason,
                    })
            else:
                # Handle cases where the row has fewer than 3 columns
                all_values = ",".join(row).split(",") # join all columns and split by comma.
                for value in all_values:
                    value = value.strip()
                    if all(c.isdigit() or c == "." or c == "/" for c in value.replace("/", "").replace(".", "")):
                        indicator_type = 'IP'
                    elif re.match(r"^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$", value):
                        indicator_type = 'URL'
                    else:
                        indicator_type = 'Hash'
                    results.append({
                        'type': indicator_type,
                        'value': value,
                        'source': source_name,
                        'timestamp': None, #timestamp is not available.
                        'listing_reason': None, #listing reason is not available.
                    })
                if "Hash Feed" in source_name:
                    for item in row:
                        if not re.match(r"^[a-f0-9]{32,128}$", item):
                            logging.error(f"Invalid hash in {source_name}: {item}, row:{row}")
                            break

        except ValueError as e:
            logging.error(f"Error parsing row in {source_name}: {e}, row:{row}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error parsing row in {source_name}: {e}, row:{row}")
            continue

    return results


def process_feed(feed_url, source_name):
    """Processes a single feed."""
    data = fetch_feed_data(feed_url)
    if data:
        if feed_url.endswith(".json"):
            return parse_json_feed(data, source_name)
        elif feed_url.endswith(".csv") or "csv" in feed_url:
            return parse_csv_feed(data, source_name)
        else:
            return parse_plain_text_feed(data, source_name)
    return []

def load_feed_urls(filepath="/Users/ne3tii/Documents/COMP3850-/Nawroj's Version of Data Collection/feed_urls.json"):
    """Loads feed URLs from a JSON file."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return {}
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON in {filepath}")
        return {}
    
def save_to_postgres(data, dbname, user, password, host, port):
    """Saves parsed data to a PostgreSQL database."""
    try:
        conn = psycopg2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
        cur = conn.cursor()

        for item in data:
            cur.execute(
                "INSERT INTO indicators (type, value, source, timestamp) VALUES (%s, %s, %s, %s)",
                (item['type'], item['value'], item['source'], item['timestamp']),
            )

        conn.commit()
        cur.close()
        conn.close()
        logging.info("Data saved to PostgreSQL successfully.")
    except psycopg2.Error as e:
        logging.error(f"Error saving to PostgreSQL: {e}")


def clear_table(db_params):
    """Clears all data from the indicators table."""
    try:
        conn = psycopg2.connect(**db_params)
        cur = conn.cursor()
        cur.execute("DELETE FROM indicators")
        cur.execute("TRUNCATE TABLE indicators RESTART IDENTITY;")
        conn.commit()
        cur.close()
        conn.close()
        logging.info("Table cleared")
    except psycopg2.Error as e:
        logging.error(f"Database error: {e}")


db_params = {
    "dbname": "postgres",
    "user": "postgres",
    "password": "1234",
    "host": "localhost",
    "port": "5433"
}

dbname = "postgres"
user = "postgres"
password = "1234"
host = "localhost"
port = "5433"

# Load feed URLs from the JSON file
feed_urls = load_feed_urls()

all_data = []
for source, url in feed_urls.items():
    logging.info(f"Processing {source} from {url}")
    feed_data = process_feed(url, source)
    all_data.extend(feed_data)

clear_table(db_params) #uncomment to clear table.
save_to_postgres(all_data, dbname, user, password, host, port) 
