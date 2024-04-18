import hw_interface
from frames import *


def sign_file_click(app):
    _external_storage, _pem_files = hw_interface.get_external_storage_and_pem_files()
    if _external_storage:
        app.set_frame(ExternalDevicesFrame, _external_storage, _pem_files)
    else:
        app.set_frame(NoExternalDevicesFrame)
