import gzip
import shutil
import os

def compress_file(filepath):
    if not os.path.exists(filepath):
        return False
    compressed_path = filepath + ".gz"
    with open(filepath, 'rb') as f_in:
        with gzip.open(compressed_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return compressed_path

def delete_old_file(filepath):
    if os.path.exists(filepath):
        os.remove(filepath)
