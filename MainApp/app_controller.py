import hw_interface
import app_storage
from frames import *


def sign_file_click(app):
    """
    Handles the event when the 'Sign File' button is clicked.

    Args:
        app: The application instance.
    """
    _external_storage, _pem_files = hw_interface.get_external_storage_and_pem_files()
    if _external_storage:
        app.set_frame(ExternalDevicesFrame, _external_storage, _pem_files)
    else:
        app.set_frame(NoExternalDevicesFrame)


def decrypt_click(app, pem_file, pin, external_storage, pem_files, is_for_signing=True):
    """
    Handles the event when the 'Decrypt' button is clicked.

    Args:
        app: The application instance.
        pem_file (str): The path to the .pem file.
        pin (str): The PIN to use for decryption.
        external_storage (list): A list of paths to the detected external devices.
        pem_files (list): A list of paths to the found .pem files.
        is_for_signing (bool, optional): Whether the decryption is for signing. Defaults to True.
    """
    key = hw_interface.decrypt_rsa_key(pem_file, pin)
    file_path = app_storage.get_file_path()
    app_storage.set_key(key)
    if key is not None:
        if is_for_signing:
            app.set_frame(SignFileFrame)
        else:
            decrypt_file_click(app, file_path, key)
    else:
        app.set_frame(ExternalDevicesFrame, external_storage, pem_files, show_invalid_pin=True)


def choose_file_click(app):
    """
    Handles the event when the 'Choose File' button is clicked.

    Args:
        app: The application instance.
    """
    file_path = ctk.filedialog.askopenfilename()
    if file_path != '':
        if file_path.endswith((".html", ".txt")):
            app_storage.set_file_path(file_path)
            app.set_frame(SignFileFrame, file_path=file_path, valid_file_extension=True)
        else:
            app.set_frame(SignFileFrame, file_path=file_path, valid_file_extension=False)


def choose_file_to_verify_click(app):
    """
    Handles the event when the 'Choose File to Verify' button is clicked.

    Args:
        app: The application instance.
    """
    file_path = ctk.filedialog.askopenfilename()
    if file_path != '':
        if file_path.endswith((".html", ".txt")):
            app_storage.set_file_path(file_path)
            app.set_frame(VerifySignatureFrame, file_path=file_path, valid_file_extension=True)
        else:
            app.set_frame(VerifySignatureFrame, file_path=file_path, valid_file_extension=False)


def choose_public_key_click(app):
    """
    Handles the event when the 'Choose Public Key' button is clicked.

    Args:
        app: The application instance.
    """
    public_key_file_path = ctk.filedialog.askopenfilename()
    if public_key_file_path != '':
        if public_key_file_path.endswith(".pem"):
            app.set_frame(SelectPublicKeyAndXMLFileFrame, public_key_file_path=public_key_file_path,
                          valid_file_extension=True)
            app_storage.set_public_key_file_path(public_key_file_path)
        else:
            app.set_frame(SelectPublicKeyAndXMLFileFrame, public_key_file_path=public_key_file_path,
                          valid_file_extension=False)


def choose_xml_file_click(app, public_key_file_path=None):
    """
    Handles the event when the 'Choose XML File' button is clicked.

    Args:
        app: The application instance.
        public_key_file_path (str, optional): The path to the public RSA key. Defaults to None.
    """
    xml_file_path = ctk.filedialog.askopenfilename()
    if xml_file_path != '':
        if xml_file_path.endswith(".xml"):
            app.set_frame(SelectPublicKeyAndXMLFileFrame, public_key_file_path=public_key_file_path,
                          xml_file_path=xml_file_path, valid_file_extension=True)
        else:
            app.set_frame(SelectPublicKeyAndXMLFileFrame, public_key_file_path=public_key_file_path,
                          xml_file_path=xml_file_path, valid_file_extension=False)


def sign_click(app, file_path):
    """
    Handles the event when the 'Sign' button is clicked.

    Args:
        app: The application instance.
        file_path (str): The path to the file to sign.
    """
    key = app_storage.get_key()
    try:
        signature, signature_file_name = hw_interface.sign_file(file_path, key)
        if signature is not None:
            app.set_frame(SignFileSuccessFrame, signature_file_name)
        else:
            print("Error signing file")
    except Exception as e:
        print(f"An error occurred while signing the file: {str(e)}")


def verify_the_signature_next_click(app, file_path):
    """
    Handles the event when the 'Next' button is clicked in the 'Verify the Signature' frame.

    Args:
        app: The application instance.
        file_path (str): The path to the file to verify.
    """
    app.set_frame(SelectPublicKeyAndXMLFileFrame, file_path=file_path)


def verify_the_signature_click(app, public_key_file_path, signature_file_path):
    """
    Handles the event when the 'Verify the Signature' button is clicked.

    Args:
        app: The application instance.
        public_key_file_path (str): The path to the public RSA key.
        signature_file_path (str): The path to the XML signature file.
    """
    try:
        file_path = app_storage.get_file_path()
        verification_result = hw_interface.verify_signature(file_path, public_key_file_path, signature_file_path)
        app.set_frame(VerifySignatureResultFrame, verification_result)
    except Exception as e:
        print(f"An error occurred while verifying the signature: {str(e)}")


def encrypt_next_click(app, filepath):
    """
    Handles the event when the 'Next' button is clicked in the 'Encrypt' frame.

    Args:
        app: The application instance.
        filepath (str): The path to the file to encrypt.
    """
    app.set_frame(SelectPublicKeyFrame, file_path=filepath, valid_file_extension=True)


def decrypt_next_click(app, filepath):
    """
    Handles the event when the 'Next' button is clicked in the 'Decrypt' frame.

    Args:
        app: The application instance.
        filepath (str): The path to the file to decrypt.
    """
    _external_storage, _pem_files = hw_interface.get_external_storage_and_pem_files()
    if _external_storage:
        app.set_frame(ExternalDevicesFrame, _external_storage, _pem_files, is_for_signing=False)
    else:
        app.set_frame(NoExternalDevicesFrame)


def encrypt_choose_file_click(app):
    """
    Handles the event when the 'Choose File' button is clicked in the 'Encrypt' frame.

    Args:
        app: The application instance.
    """
    file_path = ctk.filedialog.askopenfilename()
    if file_path != '':
        if file_path.endswith((".html", ".txt")):
            app.set_frame(EncryptFrame, file_path=file_path, valid_file_extension=True)
            app_storage.set_file_path(file_path)
        else:
            app.set_frame(EncryptFrame, file_path=file_path, valid_file_extension=False)


def decrypt_choose_file_click(app):
    """
    Handles the event when the 'Choose File' button is clicked in the 'Decrypt' frame.

    Args:
        app: The application instance.
    """
    file_path = ctk.filedialog.askopenfilename()
    if file_path != '':
        if file_path.endswith((".html", ".txt")):
            app.set_frame(DecryptFrame, file_path=file_path, valid_file_extension=True)
            app_storage.set_file_path(file_path)
        else:
            app.set_frame(DecryptFrame, file_path=file_path, valid_file_extension=False)


def encrypt_choose_public_key_click(app):
    """
    Handles the event when the 'Choose Public Key' button is clicked in the 'Encrypt' frame.

    Args:
        app: The application instance.
    """
    public_key_file_path = ctk.filedialog.askopenfilename()
    file_path = app_storage.get_file_path()
    if public_key_file_path != '':
        if public_key_file_path.endswith(".pem"):
            app.set_frame(SelectPublicKeyFrame, file_path=file_path, public_key_file_path=public_key_file_path,
                          valid_file_extension=True)
            app_storage.set_public_key_file_path(public_key_file_path)
        else:
            app.set_frame(SelectPublicKeyFrame, file_path=file_path, public_key_file_path=public_key_file_path,
                          valid_file_extension=False)


def decrypt_choose_private_key_click(app):
    """
    Handles the event when the 'Choose Private Key' button is clicked in the 'Decrypt' frame.

    Args:
        app: The application instance.
    """
    private_key_file_path = ctk.filedialog.askopenfilename()
    file_path = app_storage.get_file_path()
    if private_key_file_path != '':
        if private_key_file_path.endswith(".pem"):
            app.set_frame(SelectPrivateKeyFrame, file_path=file_path, private_key_file_path=private_key_file_path,
                          valid_file_extension=True)
            app_storage.set_public_key_file_path(private_key_file_path)
        else:
            app.set_frame(SelectPrivateKeyFrame, file_path=file_path, private_key_file_path=private_key_file_path,
                          valid_file_extension=False)


def encrypt_file_click(app, file_path, public_key_file_path):
    """
    Handles the event when the 'Encrypt File' button is clicked.

    Args:
        app: The application instance.
        file_path (str): The path to the file to encrypt.
        public_key_file_path (str): The path to the public RSA key.
    """
    try:
        encrypted_file_path = hw_interface.encrypt_file(file_path, public_key_file_path)
        if encrypted_file_path != '' and encrypted_file_path is not None:
            app.set_frame(ShowResultFrame, result="File encrypted successfully",
                          success=True, path=encrypted_file_path)
        else:
            app.set_frame(ShowResultFrame, result="Error while encrypting the file",
                          success=False)
    except Exception as e:
        print(f"An error occurred while encrypting the file: {str(e)}")


def decrypt_file_click(app, file_path, private_key_file_path):
    """
    Handles the event when the 'Decrypt File' button is clicked.

    Args:
        app: The application instance.
        file_path (str): The path to the file to decrypt.
        private_key_file_path (str): The path to the private RSA key.
    """
    decrypted_file_path = hw_interface.decrypt_file(file_path, private_key_file_path)
    if decrypted_file_path != '' and decrypted_file_path is not None:
        app.set_frame(ShowResultFrame, result="File decrypted successfully",
                      success=True, path=decrypted_file_path)
    else:
        app.set_frame(ShowResultFrame, result="Error while decrypting the file",
                      success=False)
