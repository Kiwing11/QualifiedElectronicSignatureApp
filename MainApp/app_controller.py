import frames
import hw_interface
import key_storage
from frames import *


def sign_file_click(app):
    _external_storage, _pem_files = hw_interface.get_external_storage_and_pem_files()
    if _external_storage:
        app.set_frame(ExternalDevicesFrame, _external_storage, _pem_files)
    else:
        app.set_frame(NoExternalDevicesFrame)


def decrypt_click(app, pem_file, pin, external_storage, pem_files):
    key = hw_interface.decrypt_rsa_key(pem_file, pin)
    key_storage.set_key(key)
    if key is not None:
        app.set_frame(SignFileFrame)
    else:
        app.set_frame(ExternalDevicesFrame, external_storage, pem_files, show_invalid_pin=True)


def choose_file_click(app):
    file_path = ctk.filedialog.askopenfilename()
    if file_path is not None:
        if file_path.endswith((".pdf", ".txt")):
            app.set_frame(SignFileFrame, file_path=file_path, valid_file_extension=True)
        else:
            app.set_frame(SignFileFrame, file_path=file_path, valid_file_extension=False)


def sign_click(app, file_path):
    key = key_storage.get_key()
    signature = hw_interface.sign_file(file_path, key)