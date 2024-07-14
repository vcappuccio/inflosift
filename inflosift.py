import os
import sqlite3
import argparse
import logging
from datetime import datetime
import re
import hashlib
import json
import stat
import pandas as pd
import mimetypes
from ollama import Client
import time  # Add this import at the top of the file

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def init_db():
    """Initialize the SQLite database and create necessary tables."""
    logging.info("Initializing database...")
    conn = sqlite3.connect('file_database2.db')
    c = conn.cursor()

    # Create tables with detailed comments
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY, 
                  path TEXT,              -- Full path of the file
                  filename TEXT,          -- Name of the file
                  type TEXT,              -- File type/extension
                  content TEXT,           -- Full content of the file
                  timestamps TEXT,        -- JSON array of timestamps found in the file
                  content_hash TEXT,      -- MD5 hash of the file content
                  metadata TEXT)          -- JSON object with file metadata
    ''')
    c.execute('''CREATE TABLE IF NOT EXISTS lines
                 (id INTEGER PRIMARY KEY, 
                  file_id INTEGER,        -- Foreign key to files table
                  line_number INTEGER,    -- Line number in the file
                  content TEXT,           -- Content of the line
                  FOREIGN KEY(file_id) REFERENCES files(id))
    ''')
    c.execute('''CREATE TABLE IF NOT EXISTS ptop_data
                 (id INTEGER PRIMARY KEY, 
                  timestamp TEXT,        -- Timestamp of the data
                  pid INTEGER,           -- Process ID
                  cpu_usage REAL,        -- CPU usage percentage
                  memory_usage REAL,     -- Memory usage in MB
                  process_name TEXT)     -- Name of the process
    ''')
    c.execute('''CREATE TABLE IF NOT EXISTS smaps_data
                 (id INTEGER PRIMARY KEY, 
                  timestamp TEXT,        -- Timestamp of the data
                  pid INTEGER,           -- Process ID
                  size INTEGER,          -- Total size in bytes
                  rss INTEGER,           -- Resident Set Size in bytes
                  pss INTEGER,           -- Proportional Set Size in bytes
                  shared_clean INTEGER,  -- Shared Clean in bytes
                  shared_dirty INTEGER,  -- Shared Dirty in bytes
                  private_clean INTEGER,  -- Private Clean in bytes
                  private_dirty INTEGER,  -- Private Dirty in bytes
                  referenced INTEGER,     -- Referenced in bytes
                  anonymous INTEGER,      -- Anonymous in bytes
                  swap INTEGER,           -- Swap in bytes
                  kernel_page_size INTEGER, -- Kernel Page Size in bytes
                  command TEXT)           -- Command name
    ''')
    c.execute('''CREATE TABLE IF NOT EXISTS syslog
                 (id INTEGER PRIMARY KEY,
                  timestamp TEXT,
                  facility TEXT,
                  hostname TEXT,
                  process_name TEXT,
                  pid TEXT,
                  message TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS support_syslog
                 (id INTEGER PRIMARY KEY,
                  timestamp TEXT,
                  facility TEXT,
                  hostname TEXT,
                  process_name TEXT,
                  pid TEXT,
                  message TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS infoblox
                 (id INTEGER PRIMARY KEY,
                  timestamp TEXT,
                  facility TEXT,
                  hostname TEXT,
                  process_name TEXT,
                  pid TEXT,
                  message TEXT)''')

    conn.commit()
    logging.info("Database initialization complete.")
    return conn

def check_and_update_schema(conn):
    """Check and update the database schema if necessary."""
    logging.info("Checking and updating database schema...")
    c = conn.cursor()
    
    # List of expected columns in the files table
    expected_columns = ['id', 'path', 'filename', 'type', 'content', 'timestamps', 
                        'content_hash', 'metadata']
    
    # Check existing columns
    c.execute("PRAGMA table_info(files)")
    existing_columns = [column[1] for column in c.fetchall()]
    
    # Add any missing columns
    for column in expected_columns:
        if column not in existing_columns:
            c.execute(f"ALTER TABLE files ADD COLUMN {column} TEXT")
            logging.info(f"Added {column} column to files table")
    
    conn.commit()
    logging.info("Schema check and update complete.")

def extract_timestamps(content):
    """Extract timestamps from the content using a regular expression."""
    logging.info("Extracting timestamps...")
    start_time = time.time()
    timestamp_pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
    matches = re.findall(timestamp_pattern, content)
    result = matches if matches else [datetime.now().isoformat()]
    logging.info(f"Timestamp extraction complete. Time taken: {time.time() - start_time:.2f} seconds")
    return result

def extract_metadata(content, file_type):
    """Extract metadata from the file content."""
    logging.info("Extracting metadata...")
    start_time = time.time()
    metadata = {
        'word_count': len(content.split()),
        'char_count': len(content),
        'lines': content.count('\n') + 1,
        'unique_words': len(set(content.split())),
        'average_word_length': sum(len(word) for word in content.split()) / len(content.split()) if content.split() else 0,
    }
    
    if file_type == 'log':
        metadata['log_level_counts'] = {
            'INFO': content.count('INFO'),
            'WARNING': content.count('WARNING'),
            'ERROR': content.count('ERROR'),
            'CRITICAL': content.count('CRITICAL'),
        }
    
    logging.info(f"Metadata extraction complete. Extracted metadata: {metadata}")
    logging.info(f"Word count: {metadata['word_count']}")
    logging.info(f"Character count: {metadata['char_count']}")
    logging.info(f"Line count: {metadata['lines']}")
    logging.info(f"Unique word count: {metadata['unique_words']}")
    logging.info(f"Average word length: {metadata['average_word_length']:.2f}")
    
    if file_type == 'log':
        logging.info(f"Log level counts: {metadata['log_level_counts']}")
        logging.info(f"INFO count: {metadata['log_level_counts']['INFO']}")
        logging.info(f"WARNING count: {metadata['log_level_counts']['WARNING']}")
        logging.info(f"ERROR count: {metadata['log_level_counts']['ERROR']}")
        logging.info(f"CRITICAL count: {metadata['log_level_counts']['CRITICAL']}")
    
    logging.info(f"Time taken for metadata extraction: {time.time() - start_time:.2f} seconds")
    return json.dumps(metadata)

def process_file_chunk(content, chunk_size=1000000):
    """Process the file content in chunks to handle large files."""
    for i in range(0, len(content), chunk_size):
        yield content[i:i+chunk_size]

def parse_syslog_line(line, previous_entry=None):
    syslog_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\s+(\w+)\s+(\S+)\s+(\S+)\[?(\d*)\]?:\s*(.*)'
    infoblox_pattern = r'\[(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\]\s+\((\d+)\s+([^)]+)\)\s+(.+)'
    infoblox_pattern_2 = r'\[\s*TIME NOT KNOWN\s*\]\s+\((\d+)\)\s+([^:]+):\s*(.+)'
    
    syslog_match = re.match(syslog_pattern, line)
    if syslog_match:
        timestamp, facility, hostname, process_name, pid, message = syslog_match.groups()
        return {
            'timestamp': timestamp,
            'facility': facility,
            'hostname': hostname,
            'process_name': process_name,
            'pid': pid,
            'message': message
        }, None
    
    infoblox_match = re.match(infoblox_pattern, line)
    if infoblox_match:
        timestamp, pid, process, message = infoblox_match.groups()
        return {
            'timestamp': datetime.strptime(timestamp, '%Y/%m/%d %H:%M:%S.%f').strftime('%Y-%m-%dT%H:%M:%S+00:00'),
            'facility': 'infoblox',
            'hostname': 'unknown',
            'process_name': process.split('/')[-1],
            'pid': pid,
            'message': message
        }, None
    
    infoblox_match_2 = re.match(infoblox_pattern_2, line)
    if infoblox_match_2:
        pid, process, message = infoblox_match_2.groups()
        return {
            'timestamp': 'TIME NOT KNOWN',
            'facility': 'infoblox',
            'hostname': 'unknown',
            'process_name': process.split('/')[-1],
            'pid': pid,
            'message': message
        }, None
    
    # If no match and we have a previous entry, this line is likely a continuation
    if previous_entry:
        previous_entry['message'] += '\n' + line.strip()
        return previous_entry, None
    
    return None, line.strip()  # Return the unmatched line for potential future processing

def process_log_file(file_path, conn, table_name):
    c = conn.cursor()
    
    logging.info(f"Processing log file: {file_path} for table: {table_name}")
    
    try:
        with open(file_path, 'r') as file:
            previous_entry = None
            unmatched_line = None
            for line_num, line in enumerate(file, 1):
                parsed, unmatched = parse_syslog_line(line, previous_entry)
                if parsed:
                    if previous_entry and previous_entry != parsed:
                        c.execute(f"INSERT INTO {table_name} (timestamp, facility, hostname, process_name, pid, message) VALUES (?, ?, ?, ?, ?, ?)",
                                  (previous_entry['timestamp'], previous_entry['facility'], previous_entry['hostname'], 
                                   previous_entry['process_name'], previous_entry['pid'], previous_entry['message']))
                    previous_entry = parsed
                elif unmatched:
                    if previous_entry:
                        previous_entry['message'] += '\n' + unmatched
                    else:
                        logging.warning(f"Unmatched line {line_num} in {file_path}: {unmatched}")
            
            # Insert the last entry if it exists
            if previous_entry:
                c.execute(f"INSERT INTO {table_name} (timestamp, facility, hostname, process_name, pid, message) VALUES (?, ?, ?, ?, ?, ?)",
                          (previous_entry['timestamp'], previous_entry['facility'], previous_entry['hostname'], 
                           previous_entry['process_name'], previous_entry['pid'], previous_entry['message']))
        
        conn.commit()
        logging.info(f"Successfully processed and stored log file: {file_path}")
    except Exception as e:
        logging.error(f"Error processing log file {file_path}: {str(e)}")
        conn.rollback()

def process_json_file(file_path, conn):
    logging.info(f"Processing JSON file: {file_path}")
    c = conn.cursor()
    
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            json_data = json.loads(content)
            
        file_name = os.path.basename(file_path)
        
        # Convert JSON to string for storage
        json_string = json.dumps(json_data)
        
        timestamps = json.dumps(extract_timestamps(content))
        content_hash = hashlib.md5(content.encode()).hexdigest()
        metadata = extract_metadata(content, 'json')
        
        c.execute('''INSERT INTO files (path, filename, type, content, timestamps, content_hash, metadata)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (file_path, file_name, 'json', json_string, timestamps, content_hash, metadata))
        
        file_id = c.lastrowid
        
        # Store each key-value pair as a separate line
        def process_json_item(item, parent_key=''):
            if isinstance(item, dict):
                for k, v in item.items():
                    new_key = f"{parent_key}.{k}" if parent_key else k
                    process_json_item(v, new_key)
            elif isinstance(item, list):
                for i, v in enumerate(item):
                    new_key = f"{parent_key}[{i}]"
                    process_json_item(v, new_key)
            else:
                c.execute('''INSERT INTO lines (file_id, line_number, content)
                             VALUES (?, ?, ?)''', (file_id, 0, f"{parent_key}: {item}"))
        
        process_json_item(json_data)
        
        conn.commit()
        logging.info(f"Successfully processed and stored JSON file: {file_path}")
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in file {file_path}: {str(e)}")
        conn.rollback()
    except Exception as e:
        logging.error(f"Error processing JSON file {file_path}: {str(e)}")
        conn.rollback()

def is_json_file(file_path):
    try:
        with open(file_path, 'r') as f:
            json.load(f)
        return True
    except json.JSONDecodeError:
        return False
    except Exception:
        return False
    
def process_ptop(file_path):
    logging.info(f"Processing ptop file: {file_path}")
    timestamps = []
    pids = []
    cpu_usages = []
    memory_usages = []
    process_names = []
    smaps_data = []

    top_pattern = re.compile(r'TOP\s+(\d+)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)\s+\(([\d.]+)\s+([\d.]+)\)\s+\d\s+\((.+)\)')
    time_pattern = re.compile(r'TIME\s+\d+\.\d+\s+\d+\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})')
    smaps_pattern = re.compile(
        r'SMAPS (\d+) s/r/r-/sw (\d+) (\d+) (\d+) (\d+) s (\d+) (\d+) p (\d+) (\d+) sh (\d+) (\d+) h (\d+)  c (.+)'
    )

    current_time = None
    try:
        with open(file_path, 'r') as file:
            for line_num, line in enumerate(file, 1):
                time_match = time_pattern.match(line)
                if time_match:
                    current_time = pd.to_datetime(time_match.group(1))
                top_match = top_pattern.match(line)
                if top_match and current_time:
                    timestamps.append(current_time)
                    pids.append(int(top_match.group(1)))
                    cpu_usages.append(float(top_match.group(3)))
                    memory_usages.append(float(top_match.group(4)))
                    process_names.append(top_match.group(7))
                smaps_match = smaps_pattern.match(line)
                if smaps_match and current_time:
                    smaps_data.append({
                        'Timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'PID': int(smaps_match.group(1)),
                        'Total_Size': int(smaps_match.group(2)),
                        'Rss': int(smaps_match.group(3)),
                        'Pss': int(smaps_match.group(4)),
                        'Shared_Clean': int(smaps_match.group(5)),
                        'Shared_Dirty': int(smaps_match.group(6)),
                        'Private_Clean': int(smaps_match.group(7)),
                        'Private_Dirty': int(smaps_match.group(8)),
                        'Referenced': int(smaps_match.group(9)),
                        'Anonymous': int(smaps_match.group(10)),
                        'Swap': int(smaps_match.group(11)),
                        'KernelPageSize': int(smaps_match.group(12)),
                        'Command': smaps_match.group(13)
                    })
    except Exception as e:
        logging.error(f"Error reading ptop file {file_path}: {str(e)}")
        return None, None

    if not timestamps:
        logging.warning(f"No data extracted from ptop file: {file_path}")
        return None, None

    top_data = pd.DataFrame({
        'Timestamp': [t.strftime('%Y-%m-%dT%H:%M:%S+00:00') for t in timestamps],
        'PID': pids,
        'CPU_Usage': cpu_usages,
        'Memory_Usage': memory_usages,
        'Process_Name': process_names
    })

    smaps_df = pd.DataFrame(smaps_data)
    smaps_df['Timestamp'] = pd.to_datetime(smaps_df['Timestamp']).dt.strftime('%Y-%m-%dT%H:%M:%S+00:00')

    logging.info(f"Successfully processed ptop file: {file_path}")
    return top_data, smaps_df

def is_text_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read(1024)  # Try to read the first 1024 bytes
        return True
    except UnicodeDecodeError:
        return False

def process_file(conn, file_path, file_name, file_type):
    
    if file_name == "file_database2.db":
        return
    
    if is_json_file(file_path):
        process_json_file(file_path, conn)
    elif file_name.startswith('ptop'):
        process_ptop_file(file_path, conn)
    elif file_name.startswith('syslog') or 'syslog' in file_name or file_name.startswith('infoblox'):
        table_name = 'syslog' if file_name.startswith('syslog') else ('support_syslog' if 'support_syslog' in file_name else 'infoblox')
        process_log_file(file_path, conn, table_name)
    elif is_text_file(file_path):
        process_generic_file(file_path, conn)
    else:
        logging.info(f"Skipping non-text file: {file_path}")

def process_generic_file(file_path, conn):
    logging.info(f"Processing generic file: {file_path}")
    c = conn.cursor()
    
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            
        file_name = os.path.basename(file_path)
        file_type = os.path.splitext(file_name)[1][1:] or 'unknown'
        
        timestamps = json.dumps(extract_timestamps(content))
        content_hash = hashlib.md5(content.encode()).hexdigest()
        metadata = extract_metadata(content, file_type)
        
        c.execute('''INSERT INTO files (path, filename, type, content, timestamps, content_hash, metadata)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (file_path, file_name, file_type, content, timestamps, content_hash, metadata))
        
        file_id = c.lastrowid
        
        for line_number, line in enumerate(content.splitlines(), 1):
            c.execute('''INSERT INTO lines (file_id, line_number, content)
                         VALUES (?, ?, ?)''', (file_id, line_number, line))
        
        conn.commit()
        logging.info(f"Successfully processed and stored generic file: {file_path}")
    except Exception as e:
        logging.error(f"Error processing generic file {file_path}: {str(e)}")
        conn.rollback()

def process_ptop_file(file_path, conn):
    logging.info(f"Processing ptop file: {file_path}")
    top_data, smaps_df = process_ptop(file_path)
    if top_data is not None and smaps_df is not None:
        c = conn.cursor()
        for _, row in top_data.iterrows():
            c.execute("INSERT INTO ptop_data (timestamp, pid, cpu_usage, memory_usage, process_name) VALUES (?, ?, ?, ?, ?)",
                      (row['Timestamp'], int(row['PID']), float(row['CPU_Usage']), float(row['Memory_Usage']), str(row['Process_Name'])))
        for _, row in smaps_df.iterrows():
            c.execute("INSERT INTO smaps_data (timestamp, pid, size, rss, pss, shared_clean, shared_dirty, private_clean, private_dirty, referenced, anonymous, swap, kernel_page_size, command) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (row['Timestamp'], int(row['PID']), int(row['Total_Size']), int(row['Rss']), int(row['Pss']), int(row['Shared_Clean']), int(row['Shared_Dirty']), int(row['Private_Clean']), int(row['Private_Dirty']), int(row['Referenced']), int(row['Anonymous']), int(row['Swap']), int(row['KernelPageSize']), str(row['Command'])))
        conn.commit()
        logging.info(f"Processed and stored ptop file: {file_path}")
    else:
        logging.warning(f"Failed to process ptop file: {file_path}")

def list_files(directory, conn):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_type = os.path.splitext(file)[1][1:] or 'unknown'
            process_file(conn, file_path, file, file_type)


def ollama_query(query, conn, focus_area=None):
    """Execute a natural language query using Ollama and analyze the results."""
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = c.fetchall()
    
    context = "This is a SQLite database with the following tables and their columns:\n\n"
    for table in tables:
        context += f"Table: {table[0]}\n"
        c.execute(f"PRAGMA table_info({table[0]})")
        columns = c.fetchall()
        for col in columns:
            col_name, col_type = col[1], col[2]
            context += f"  - {col_name} ({col_type})\n"
        context += "\n"
    
    client = Client()
    
    system_content = f'''You are an expert in analyzing log files, particularly for {focus_area} issues. {context}
    Generate a SQLite-compatible SQL query. Do not include any explanatory text, only the SQL query.
    Use strftime('%s', 'now') - 86400 for timestamp comparisons instead of NOW() or TIMESTAMPDIFF.
    Assume timestamps are stored as TEXT in ISO format (YYYY-MM-DDTHH:MM:SS).
    Only use columns that are explicitly listed in the schema provided.
    For DHCP failover issues, focus on the 'syslog', 'support_syslog', and 'infoblox' tables, and look for messages containing 'DHCP' or 'failover'.'''
    
    user_content = f"Generate a SQLite-compatible SQL query to find {focus_area} issues in the last 24 hours. Include relevant filters in the WHERE clause and ensure timestamp information is in the SELECT statement."
    
    response = client.chat(model='llama3big:latest', messages=[
        {
            'role': 'system',
            'content': system_content
        },
        {
            'role': 'user',
            'content': user_content
        }
    ])
    
    sql_query = response['message']['content'].strip()
    
    print(f"Generated SQL Query:\n{sql_query}\n")

    if sql_query.upper().startswith("SELECT"):
        try:
            c.execute(sql_query)
            query_result = c.fetchall()
            
            analysis_prompt = f"Analyze the following query results in the context of {focus_area} issues:\n\nQuery: {sql_query}\n\nResults: {query_result}\n\nProvide insights, identify patterns, and suggest potential issues or solutions. Pay special attention to the timestamps and how they relate to the sequence of events."
            
            analysis_response = client.chat(model='llama3big:latest', messages=[
                {
                    'role': 'system',
                    'content': 'You are an expert in analyzing log data and providing insightful summaries. Focus on the implications of the data for system performance, stability, and potential issues.'
                },
                {
                    'role': 'user',
                    'content': analysis_prompt
                }
            ])
            
            return f"Results: {query_result}\n\nAnalysis: {analysis_response['message']['content']}"
        except sqlite3.OperationalError as e:
            error_message = str(e)
            correction_prompt = f"The SQL query resulted in an error: {error_message}. Please correct the query based on this error and the provided schema. Only use columns that exist in the tables."
            
            correction_response = client.chat(model='llama3big:latest', messages=[
                {
                    'role': 'system',
                    'content': system_content
                },
                {
                    'role': 'user',
                    'content': correction_prompt
                }
            ])
            
            corrected_sql_query = correction_response['message']['content'].strip()
            print(f"Corrected SQL Query:\n{corrected_sql_query}\n")
            
            try:
                c.execute(corrected_sql_query)
                query_result = c.fetchall()
                return f"Results: {query_result}\n\nNote: The original query was corrected due to an error."
            except Exception as e:
                return f"Error executing corrected query: {str(e)}"
        except Exception as e:
            return f"Error executing query: {str(e)}"
    else:
        return f"Invalid SQL query generated: {sql_query}"   

def main():
    """Main function to handle command-line arguments and execute the program."""
    parser = argparse.ArgumentParser(description="Process and query files.")
    parser.add_argument("--directory", default=os.getcwd(), help="Directory to process")
    parser.add_argument("--query", help="Natural language query for Ollama")
    parser.add_argument("--focus", help="Focus area for the query (e.g., 'DHCP failover')")
    args = parser.parse_args()

    conn = init_db()
    check_and_update_schema(conn)

    if args.query:
        result = ollama_query(args.query, conn, focus_area=args.focus)
        print(result)
    else:
        list_files(args.directory, conn)
        logging.info(f"Directory contents processed and stored in database")

    conn.close()

if __name__ == '__main__':
    main()