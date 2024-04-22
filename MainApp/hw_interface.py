import win32api
import win32file
import os


def detect_external_devices():
    drives = win32api.GetLogicalDriveStrings()
    drives = drives.split('\000')[:-1]
    external_devices = []
    for drive in drives:
        drive_type = win32file.GetDriveType(drive)
        if drive_type == win32file.DRIVE_REMOVABLE:
            external_devices.append(drive)
    return external_devices


def find_pem_files(drives):
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
    external_storage = detect_external_devices()
    pem_files = find_pem_files(external_storage)
    return external_storage, pem_files
