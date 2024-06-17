import win32api
import win32file
import os
import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from xml.etree import ElementTree as ET
from xml.dom.minidom import parseString
from uuid import getnode as get_mac
from datetime import datetime


def detect_external_devices():
    """
    Detects all external devices connected to the system.

    Returns:
        list: A list of paths to the detected external devices.
    """
    drives = win32api.GetLogicalDriveStrings()
    drives = drives.split('\000')[:-1]
    external_devices = []
    for drive in drives:
        drive_type = win32file.GetDriveType(drive)
        if drive_type == win32file.DRIVE_REMOVABLE:
            external_devices.append(drive)
    return external_devices


def find_pem_files(drives):
    """
    Finds all .pem files in the given drives.

    Args:
        drives (list): A list of paths to the drives to search in.

    Returns:
        list: A list of paths to the found .pem files. None if no .pem files were found.
    """
    pem_files = []
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            for file in files:
                if file.endswith(".pem"):
                    pem_files.append(os.path.join(root, file))
    if not pem_files:
        return None
    return pem_files


def get_external_storage_and_pem_files():
    """
    Detects all external devices and finds all .pem files in them.

    Returns:
        tuple: A tuple containing a list of paths to the detected external devices and a list of paths to the found .pem files.
    """
    external_storage = detect_external_devices()
    pem_files = find_pem_files(external_storage)
    return external_storage, pem_files


def decrypt_rsa_key(pem_file, pin):
    """
    Decrypts an RSA key from a .pem file using a given PIN.

    Args:
        pem_file (str): The path to the .pem file.
        pin (str): The PIN to use for decryption.

    Returns:
        RSA key: The decrypted RSA key. None if an error occurred during decryption.
    """
    try:
        with open(pem_file, 'rb') as f:
            encrypted_key = f.read()

        iv = encrypted_key[:AES.block_size]
        encrypted_key = encrypted_key[AES.block_size:]

        key = hashlib.sha256(pin.encode()).digest()

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_key = cipher.decrypt(encrypted_key)

        private_key = unpad(decrypted_key, AES.block_size)

        return RSA.import_key(private_key)
    except (ValueError, KeyError) as e:
        print(f"An error occurred during decryption: {e}")
        return None


def sign_file(file_path, key):
    """
    Signs a file with a given RSA key.

    Args:
        file_path (str): The path to the file to sign.
        key (RSA key): The RSA key to sign the file with.

    Returns:
        tuple: A tuple containing the XML signature as a string and the path to the saved signature file.
    """
    with open(file_path, "rb") as file:
        file_content = file.read()

    file_hash = SHA256.new(file_content)

    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(file_hash)

    signature_xml = ET.Element("XAdES")

    file_info = ET.SubElement(signature_xml, "FileInfo")
    file_info_dict = {
        "Size": str(os.path.getsize(file_path)),
        "Extension": os.path.splitext(file_path)[1][1:],  # remove leading dot
        "ModificationDate": str(datetime.fromtimestamp(os.path.getmtime(file_path)))
    }
    for key, value in file_info_dict.items():
        ET.SubElement(file_info, key).text = value

    user_info = ET.SubElement(file_info, "UserInfo")
    user_info_dict = {
        "SigningUserName": str(os.getlogin()),
        "SigningUserMAC": str(hex(get_mac()))
    }
    for key, value in user_info_dict.items():
        ET.SubElement(user_info, key).text = value

    ET.SubElement(signature_xml, "EncryptedHash").text = base64.b64encode(signature).decode()
    ET.SubElement(signature_xml, "Timestamp").text = str(datetime.now())

    signature_xml_str = parseString(ET.tostring(signature_xml)).toprettyxml()

    signature_file_name = f"signature-{os.path.splitext(os.path.basename(file_path))[0]}.xml"
    with open(signature_file_name, "w") as xml_file:
        xml_file.write(signature_xml_str)

    return signature_xml_str, signature_file_name


def verify_signature(file_path, public_key_path, xml_file_path):
    """
    Verifies the signature of a file.

    Args:
        file_path (str): The path to the file to verify.
        public_key_path (str): The path to the public RSA key to use for verification.
        xml_file_path (str): The path to the XML signature file.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    with open(file_path, "rb") as file:
        file_content = file.read()

    file_hash = SHA256.new(file_content)

    with open(xml_file_path, "r") as signature_file:
        signature_xml = signature_file.read()

    signature_tree = ET.fromstring(signature_xml)

    with open(public_key_path, 'r') as key_file:
        public_key = RSA.import_key(key_file.read())

    signature = base64.b64decode(signature_tree.find("EncryptedHash").text)

    verifier = PKCS1_v1_5.new(public_key)

    is_signature_valid = verifier.verify(file_hash, signature)
    print(f"Is signature valid: {is_signature_valid}")

    return is_signature_valid


def encrypt_file(file_path, public_key_path):
    """
    Encrypts a file with a given public RSA key.

    Args:
        file_path (str): The path to the file to encrypt.
        public_key_path (str): The path to the public RSA key to use for encryption.

    Returns:
        bytes: The encrypted file content. None if an error occurred during encryption.
    """
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()

        with open(public_key_path, "rb") as key_file:
            public_key = RSA.import_key(key_file.read())

        cipher = PKCS1_OAEP.new(public_key)
        encrypted_file = cipher.encrypt(file_content)

        with open(file_path, "wb") as file:
            file.write(encrypted_file)

        return encrypted_file

    except (ValueError, KeyError) as e:
        print(f"An error occurred during decryption: {e}")
        return None


def decrypt_file(file_path, decrypt_key):
    """
    Decrypts a file with a given RSA key.

    Args:
        file_path (str): The path to the file to decrypt.
        decrypt_key (RSA key): The RSA key to use for decryption.

    Returns:
        bytes: The decrypted file content. None if an error occurred during decryption.
    """
    try:
        with open(file_path, "rb") as file:
            encrypted_file = file.read()

        cipher = PKCS1_OAEP.new(decrypt_key)
        decrypted_file = cipher.decrypt(encrypted_file)

        with open(file_path, "wb") as file:
            file.write(decrypted_file)

        return decrypted_file

    except (ValueError, KeyError) as e:
        print(f"An error occurred during encryption: {e}")
        return None
