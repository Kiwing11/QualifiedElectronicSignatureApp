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
    if file_path != '':
        if file_path.endswith((".pdf", ".txt")):
            key_storage.set_file_path(file_path)
            app.set_frame(SignFileFrame, file_path=file_path, valid_file_extension=True)
        else:
            app.set_frame(SignFileFrame, file_path=file_path, valid_file_extension=False)

def choose_file_to_verify_click(app):
    file_path = ctk.filedialog.askopenfilename()
    if file_path != '':
        if file_path.endswith((".pdf", ".txt")):
            key_storage.set_file_path(file_path)
            app.set_frame(VerifySignatureFrame, file_path=file_path, valid_file_extension=True)
        else:
            app.set_frame(VerifySignatureFrame, file_path=file_path, valid_file_extension=False)

def choose_public_key_click(app):
    public_key_file_path = ctk.filedialog.askopenfilename()
    if public_key_file_path != '':
        if public_key_file_path.endswith(".pem"):
            app.set_frame(SelectPublicKeyAndXMLFileFrame, public_key_file_path=public_key_file_path, valid_file_extension=True)
            key_storage.set_public_key_file_path(public_key_file_path)
        else:
            app.set_frame(SelectPublicKeyAndXMLFileFrame, public_key_file_path=public_key_file_path, valid_file_extension=False)

def choose_xml_file_click(app, public_key_file_path=None):
    xml_file_path = ctk.filedialog.askopenfilename()
    if xml_file_path != '':
        if xml_file_path.endswith(".xml"):
            app.set_frame(SelectPublicKeyAndXMLFileFrame, public_key_file_path=public_key_file_path,  xml_file_path=xml_file_path, valid_file_extension=True)
        else:
            app.set_frame(SelectPublicKeyAndXMLFileFrame, public_key_file_path=public_key_file_path,xml_file_path=xml_file_path, valid_file_extension=False)

def sign_click(app, file_path):
    key = key_storage.get_key()
    try:
        signature, signature_file_name = hw_interface.sign_file(file_path, key)
        if signature is not None:
            app.set_frame(SignFileSuccessFrame, signature_file_name)
        else:
            print("Error signing file")
    except Exception as e:
        print(f"An error occurred while signing the file: {str(e)}")

def verify_the_signature_next_click(app, file_path):
    app.set_frame(SelectPublicKeyAndXMLFileFrame, file_path=file_path)

def verify_the_signature_click(app, public_key_file_path, signature_file_path):
    try:
        file_path = key_storage.get_file_path()
        verification_result = hw_interface.verify_signature(file_path, public_key_file_path, signature_file_path)
        app.set_frame(VerifySignatureResultFrame, verification_result)
    except Exception as e:
        print(f"An error occurred while verifying the signature: {str(e)}")

def encrypt_next_click(app, filepath):
    app.set_frame(SelectPublicKeyFrame, file_path=filepath, valid_file_extension=True)

def encrypt_choose_file_click(app):
    file_path = ctk.filedialog.askopenfilename()
    if file_path != '':
        if file_path.endswith((".pdf", ".txt")):
            app.set_frame(EncryptFrame, file_path=file_path, valid_file_extension=True)
            key_storage.set_file_path(file_path)
        else:
            app.set_frame(EncryptFrame, file_path=file_path, valid_file_extension=False)

def encrypt_choose_public_key_click(app):
    public_key_file_path = ctk.filedialog.askopenfilename()
    file_path = key_storage.get_file_path()
    if public_key_file_path != '':
        if public_key_file_path.endswith(".pem"):
            app.set_frame(SelectPublicKeyFrame, file_path=file_path, public_key_file_path=public_key_file_path, valid_file_extension=True)
            key_storage.set_public_key_file_path(public_key_file_path)
        else:
            app.set_frame(SelectPublicKeyFrame, file_path=file_path, public_key_file_path=public_key_file_path, valid_file_extension=False)

def encrypt_file_click(app, file_path, public_key_file_path):
    try:
        encrypted_file_path = hw_interface.encrypt_file(file_path, public_key_file_path)
        if encrypted_file_path is not None:
            app.set_frame(ShowResultFrame, result="File encrypted successfully",
                          success=True, path=encrypted_file_path)
        else:
            app.set_frame(ShowResultFrame, result="Error while encrypting the file",
                          success=False)
    except Exception as e:
        print(f"An error occurred while encrypting the file: {str(e)}")
    pass