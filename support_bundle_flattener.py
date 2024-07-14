import os
import shutil
import tarfile
import zipfile
import gzip
import argparse
import logging
from colorama import Fore, Style, init

init(autoreset=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def decompress_file(src_path, dest_dir):
    """Decompress file if it's compressed, otherwise just copy it."""
    filename = os.path.basename(src_path)
    dest_path = os.path.join(dest_dir, filename)
    
    try:
        if src_path.endswith(('.tar.gz', '.tgz', '.tar', '.gz', '.zip')):
            print(f"{Fore.RED}Uncompressing: {src_path}{Style.RESET_ALL}")
        
        if src_path.endswith(('.tar.gz', '.tgz')):
            with tarfile.open(src_path, 'r:gz') as tar:
                tar.extractall(path=dest_dir)
            logging.info(f"Extracted {src_path} to {dest_dir}")
            return True
        elif src_path.endswith('.tar'):
            with tarfile.open(src_path, 'r') as tar:
                tar.extractall(path=dest_dir)
            logging.info(f"Extracted {src_path} to {dest_dir}")
            return True
        elif src_path.endswith('.gz') and not src_path.endswith('.tar.gz'):
            output_filename = os.path.splitext(filename)[0]
            output_path = os.path.join(dest_dir, output_filename)
            with gzip.open(src_path, 'rb') as gz_file:
                with open(output_path, 'wb') as out_file:
                    shutil.copyfileobj(gz_file, out_file)
            logging.info(f"Decompressed {src_path} to {output_path}")
            return True
        elif src_path.endswith('.zip'):
            with zipfile.ZipFile(src_path, 'r') as zip_ref:
                zip_ref.extractall(dest_dir)
            logging.info(f"Extracted {src_path} to {dest_dir}")
            return True
        else:
            shutil.copy2(src_path, dest_path)
            logging.info(f"Copied {src_path} to {dest_path}")
            return False
    except Exception as e:
        logging.error(f"Error processing file {src_path}: {str(e)}")
        return False

def process_directory(src, dest, current_depth=0):
    """Recursively process directory contents, decompressing files when necessary."""
    if current_depth > 20:  # Limit recursion depth to avoid infinite loops
        logging.warning(f"Maximum recursion depth reached for {src}")
        return

    if not os.path.exists(dest):
        os.makedirs(dest)

    for item in os.listdir(src):
        src_path = os.path.join(src, item)
        dest_path = os.path.join(dest, item)

        if os.path.isdir(src_path):
            process_directory(src_path, dest_path, current_depth + 1)
        else:
            try:
                while decompress_file(src_path, dest):
                    src_path = os.path.splitext(src_path)[0]
                    dest_path = os.path.splitext(dest_path)[0]
            except Exception as e:
                logging.error(f"Error processing {src_path}: {str(e)}")

def delete_previous_flattened(destination):
    """Delete previously flattened files and directories."""
    if os.path.exists(destination):
        shutil.rmtree(destination)
        logging.info(f"Deleted previous flattened files in {destination}")

def main():
    parser = argparse.ArgumentParser(description="Copy and decompress directory contents.")
    parser.add_argument("source", help="Source directory path")
    parser.add_argument("destination", help="Destination directory path")
    args = parser.parse_args()

    delete_previous_flattened(args.destination)
    process_directory(args.source, args.destination)
    logging.info(f"Directory contents copied and decompressed from {args.source} to {args.destination}")

if __name__ == "__main__":
    main()
