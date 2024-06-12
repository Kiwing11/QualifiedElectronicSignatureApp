key = None
public_key_file_path = None
file_path = None

def set_key(new_key):
    global key
    key = new_key

def get_key():
    return key

def set_public_key_file_path(new_path):
    global public_key_file_path
    public_key_file_path = new_path

def get_public_key_file_path():
    return public_key_file_path

def set_file_path(new_path):
    global file_path
    file_path = new_path

def get_file_path():
    return file_path
