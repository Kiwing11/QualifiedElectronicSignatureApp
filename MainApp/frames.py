import app_controller
import customtkinter as ctk


class MainFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2), weight=1)
        self.grid_columnconfigure(0, weight=1)

        sign_file_button = (ctk.CTkButton(self, text="Sign File", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.2, command=lambda: app_controller.sign_file_click(app))
                            .grid(row=0, column=0, pady=(10, 0)))

        verify_the_signature_button = (ctk.CTkButton(self, text="Verify the signature", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.2, command=lambda: app.set_frame(VerifySignatureFrame))
                          .grid(row=1, column=0, pady=(10, 0)))

        encrypt_button = (ctk.CTkButton(self, text="Encrypt", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.2, command=lambda: app.set_frame(EncryptFrame))
                          .grid(row=2, column=0, pady=(10, 0)))

        decrypt_button = (ctk.CTkButton(self, text="Decrypt", font=("Courier new", 20), width=app.width*0.5, height=app.height * 0.2, command=lambda: app.set_frame(DecryptFrame))
                          .grid(row=3, column=0, pady=(10, 10)))



class NoExternalDevicesFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure( (0, 1), weight=1)
        self.grid_columnconfigure(0, weight=1)
        label = ctk.CTkLabel(self, text="No external storage found", font=("Courier new", 20)).grid(row=0, column=0, pady=(10, 0), sticky="n")
        return_button = (ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.2, command=lambda:  app.set_frame(MainFrame))
                         .grid(row=1, column=0, pady=(10, 10)))


class ExternalDevicesFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app, external_storage, pem_files, show_invalid_pin=False, is_for_signing=True):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.grid_columnconfigure(0, weight=1)

        (ctk.CTkLabel(master=self, width=app.width*0.5, height=app.height*0.2, text="Found external storage: " + external_storage[0], font=("Courier new", 20))
         .grid(row=0, column=0, pady=(10, 0), sticky="n"))

        if pem_files is None:
            (ctk.CTkLabel(master=self, width=app.width*0.5, height=app.height*0.2,  text="No .pem file found", font=("Courier new", 20))
             .grid(row=2, column=0,  pady=(10, 20), sticky="n"))
        else:
            combobox = ctk.CTkComboBox(master=self, values=pem_files, font=("Courier new", 20), width=app.width * 0.5,
                                       height=15)
            combobox.grid(row=1, column=0, padx=10, pady=(10, 20))
            combobox.set(pem_files[0])

            if show_invalid_pin:
                (ctk.CTkLabel(master=self, width=app.width * 0.5, height=app.height*0.1, text="Invalid PIN",
                              font=("Courier new", 20), text_color="red")
                 .grid(row=3, column=0, pady=(0, 0), sticky="n"))

            pin_entry = ctk.CTkEntry(
                master=self, width=app.width * 0.5, height=30, font=("Courier new", 20), placeholder_text="Enter PIN",
                show="*"
            )
            pin_entry.grid(row=2, column=0, padx=10, pady=(0, 20))

            decrypt_button = ctk.CTkButton(self, text="Decrypt", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.1,
                                           command=lambda: app_controller.decrypt_click(app, combobox.get(), pin_entry.get(), external_storage, pem_files, is_for_signing=is_for_signing))
            decrypt_button.grid(row=4, column=0, pady=(10, 20))

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=5, column=0, pady=(10, 10))

class SignFileFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app, file_path=None, valid_file_extension=True):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.grid_columnconfigure(0, weight=1)

        file_button = ctk.CTkButton(self, text="Choose File", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.1,
                                    command=lambda: app_controller.choose_file_click(app))
        file_button.grid(row=0, column=0, pady=(10, 0))

        if file_path is not None:
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen file:", font=("Courier new", 20))
                text_label.grid(row=2, column=0, pady=10, sticky="n")

                file_path_label = ctk.CTkLabel(master=self, text=file_path, fg_color="Green", font=("Courier new", 20),
                                               width=app.width * 0.5, height=app.height * 0.1)
                file_path_label.grid(row=3, column=0, pady=10, sticky="n")

                sign_button = ctk.CTkButton(self, text="Sign file", font=("Courier new", 20), width=app.width*0.5,
                                            height=app.height*0.1, command=lambda: app_controller.sign_click(app, file_path))
                sign_button.grid(row=4, column=0, pady=10, sticky="n")
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Courier new", 20),
                                          text_color="red")
                text_label.grid(row=2, column=0, pady=20, sticky="n")

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=5, column=0, pady=(10, 10))

class SignFileSuccessFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app, signature_file_name):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)
        self.grid_columnconfigure(0, weight=1)

        file_path_label = ctk.CTkLabel(master=self, text=signature_file_name, fg_color="Green", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.1)
        file_path_label.grid(row=1, column=0, pady=10, sticky="n")

        text_label = ctk.CTkLabel(master=self, text="File signed successfully", font=("Courier new", 20))
        text_label.grid(row=0, column=0, pady=10, sticky="n")

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=2, column=0, pady=(10, 10))

class VerifySignatureFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app, file_path=None, valid_file_extension=True):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.grid_columnconfigure(0, weight=1)

        file_button = ctk.CTkButton(self, text="Choose File to verify", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.1,
                                    command=lambda: app_controller.choose_file_to_verify_click(app))
        file_button.grid(row=0, column=0, pady=(10, 0))

        if file_path is not None:
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen file:", font=("Courier new", 20))
                text_label.grid(row=2, column=0, pady=10, sticky="n")

                file_path_label = ctk.CTkLabel(master=self, text=file_path, fg_color="Green", font=("Courier new", 20),
                                               width=app.width * 0.5, height=app.height * 0.1)
                file_path_label.grid(row=3, column=0, pady=10, sticky="n")

                verify_button = ctk.CTkButton(self, text="Next", font=("Courier new", 20), width=app.width*0.5,
                                            height=app.height*0.1, command=lambda: app_controller.verify_the_signature_next_click(app, file_path))
                verify_button.grid(row=4, column=0, pady=10, sticky="n")
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Courier new", 20),
                                          text_color="red")
                text_label.grid(row=2, column=0, pady=20, sticky="n")

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width*0.5, height=app.height*0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=5, column=0, pady=(10, 10))

class SelectPublicKeyAndXMLFileFrame(ctk.CTkFrame):
    def __init__(self, parent: any, app, public_key_file_path=None, valid_file_extension=True, xml_file_path=None, file_path=None):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)
        self.grid_columnconfigure((0, 1), weight=1)

        # Column 1: Public key selection
        public_key_file_button = ctk.CTkButton(self, text="Choose public key", font=("Courier new", 20),
                                               width=app.width * 0.5, height=app.height * 0.1,
                                               command=lambda: app_controller.choose_public_key_click(app))
        public_key_file_button.grid(row=0, column=0, pady=(10, 0), padx=(10, 5), sticky="ew")

        if public_key_file_path is not None:
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen public key:",  font=("Courier new", 20))
                text_label.grid(row=1, column=0, pady=10, padx=(10, 5), sticky="ew")

                public_key_file_path_label = ctk.CTkLabel(master=self, text=public_key_file_path, fg_color="Green",
                                                          font=("Courier new", 20),
                                                          width=app.width * 0.5, height=app.height * 0.1)
                public_key_file_path_label.grid(row=2, column=0, pady=10, padx=(10, 5), sticky="ew")
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Courier new", 20),
                                          text_color="red")
                text_label.grid(row=1, column=0, pady=20, padx=(10, 5), sticky="ew")

        # Column 2: XML file selection
        xml_file_button = ctk.CTkButton(self, text="Choose XML file", font=("Courier new", 20),
                                        width=app.width * 0.5, height=app.height * 0.1,
                                        command=lambda: app_controller.choose_xml_file_click(app, public_key_file_path))
        xml_file_button.grid(row=0, column=1, pady=(10, 0), padx=(5, 10), sticky="ew")

        if xml_file_path is not None:
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen XML file:", font=("Courier new", 20))
                text_label.grid(row=1, column=1, pady=10, padx=(5, 10), sticky="ew")

                xml_file_path_label = ctk.CTkLabel(master=self, text=xml_file_path, fg_color="Green",
                                                   font=("Courier new", 20),
                                                   width=app.width * 0.5, height=app.height * 0.1)
                xml_file_path_label.grid(row=2, column=1, pady=10, padx=(5, 10), sticky="ew")
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Courier new", 20),
                                          text_color="red")
                text_label.grid(row=1, column=1, pady=20, padx=(5, 10), sticky="ew")

        if xml_file_path is not None and public_key_file_path is not None:
            verify_button = ctk.CTkButton(self, text="Verify", font=("Courier new", 20), width=app.width * 0.5,
                                          height=app.height * 0.1, command=lambda: app_controller.
                                          verify_the_signature_click(app=app, public_key_file_path=public_key_file_path, signature_file_path=xml_file_path))
            verify_button.grid(row=3, column=0, columnspan=2, pady=(10, 20), sticky="n")

        # Return button spanning two columns
        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width * 0.5,
                                      height=app.height * 0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=4, column=0, columnspan=2, pady=(10, 10), sticky="n")

class VerifySignatureResultFrame(ctk.CTkFrame):
    def __init__(self, parent: any, app, is_signature_valid):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)
        self.grid_columnconfigure(0, weight=1)

        if is_signature_valid:
            text_label = ctk.CTkLabel(master=self, text="Signature is valid", font=("Courier new", 30), fg_color="Green")
            text_label.grid(row=1, column=0, pady=20, sticky="n")
        else:
            text_label = ctk.CTkLabel(master=self, text="Signature is invalid", font=("Courier new", 20), fg_color="Red")
            text_label.grid(row=1, column=0, pady=20, sticky="n")

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width * 0.5,
                                      height=app.height * 0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=2, column=0, pady=(10, 10))

class EncryptFrame(ctk.CTkFrame):
    def __init__(self, parent: any, app, file_path=None, valid_file_extension=True):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.grid_columnconfigure(0, weight=1)

        file_button = ctk.CTkButton(self, text="Choose File", font=("Courier new", 20), width=app.width * 0.5,
                                    height=app.height * 0.1,
                                    command=lambda: app_controller.encrypt_choose_file_click(app))
        file_button.grid(row=0, column=0, pady=(10, 0))

        if file_path is not None:
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen file:", font=("Courier new", 20))
                text_label.grid(row=2, column=0, pady=10, sticky="n")

                file_path_label = ctk.CTkLabel(master=self, text=file_path, fg_color="Green", font=("Courier new", 20),
                                               width=app.width * 0.5, height=app.height * 0.1)
                file_path_label.grid(row=3, column=0, pady=10, sticky="n")

                sign_button = ctk.CTkButton(self, text="Next", font=("Courier new", 20), width=app.width * 0.5,
                                            height=app.height * 0.1,
                                            command=lambda: app_controller.encrypt_next_click(app, file_path))
                sign_button.grid(row=4, column=0, pady=10, sticky="n")
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Courier new", 20),
                                          text_color="red")
                text_label.grid(row=2, column=0, pady=20, sticky="n")

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width * 0.5,
                                      height=app.height * 0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=5, column=0, pady=(10, 10))

class DecryptFrame(ctk.CTkFrame):
    def __init__(self, parent: any, app, file_path=None, valid_file_extension=True):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.grid_columnconfigure(0, weight=1)

        file_button = ctk.CTkButton(self, text="Choose File", font=("Courier new", 20), width=app.width * 0.5,
                                    height=app.height * 0.1,
                                    command=lambda: app_controller.decrypt_choose_file_click(app))
        file_button.grid(row=0, column=0, pady=(10, 0))

        if file_path is not None:
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen file:", font=("Courier new", 20))
                text_label.grid(row=2, column=0, pady=10, sticky="n")

                file_path_label = ctk.CTkLabel(master=self, text=file_path, fg_color="Green", font=("Courier new", 20),
                                               width=app.width * 0.5, height=app.height * 0.1)
                file_path_label.grid(row=3, column=0, pady=10, sticky="n")

                sign_button = ctk.CTkButton(self, text="Next", font=("Courier new", 20), width=app.width * 0.5,
                                            height=app.height * 0.1,
                                            command=lambda: app_controller.decrypt_next_click(app, file_path))
                sign_button.grid(row=4, column=0, pady=10, sticky="n")
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Courier new", 20),
                                          text_color="red")
                text_label.grid(row=2, column=0, pady=20, sticky="n")

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width * 0.5,
                                      height=app.height * 0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=5, column=0, pady=(10, 10))

class SelectPublicKeyFrame(ctk.CTkFrame):
    def __init__(self, parent: any, app, public_key_file_path=None, valid_file_extension=True,
                 file_path=None):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Column 1: Public key selection
        public_key_file_button = ctk.CTkButton(self, text="Choose public key", font=("Courier new", 20),
                                               width=app.width * 0.5, height=app.height * 0.1,
                                               command=lambda: app_controller.encrypt_choose_public_key_click(app))
        public_key_file_button.grid(row=0, column=0, pady=(10, 0))

        if public_key_file_path is not None:
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen public key:", font=("Courier new", 20))
                text_label.grid(row=1, column=0, pady=10, padx=(10, 5), sticky="ew")

                public_key_file_path_label = ctk.CTkLabel(master=self, text=public_key_file_path, fg_color="Green",
                                                          font=("Courier new", 20),
                                                          width=app.width * 0.5, height=app.height * 0.1)
                public_key_file_path_label.grid(row=2, column=0, pady=10, padx=(10, 5))

                encrypt_button = ctk.CTkButton(self, text="Encrypt file", font=("Courier new", 20), width=app.width * 0.5,
                                               height=app.height * 0.1,
                                               command=lambda: app_controller.encrypt_file_click(app, file_path=file_path,
                                                                                                 public_key_file_path=public_key_file_path))

                encrypt_button.grid(row=3, column=0, pady=10, padx=(10, 5))
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Courier new", 20),
                                          text_color="red")
                text_label.grid(row=1, column=0, pady=20, padx=(10, 5))

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width * 0.5,
                                      height=app.height * 0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=4, column=0, pady=(10, 10))

class SelectPrivateKeyFrame(ctk.CTkFrame):
    def __init__(self, parent: any, app, private_key_file_path=None, valid_file_extension=True,
                 file_path=None):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)
        self.grid_columnconfigure(0, weight=1)

        private_key_file_button = ctk.CTkButton(self, text="Choose private key", font=("Courier new", 20),
                                               width=app.width * 0.5, height=app.height * 0.1,
                                               command=lambda: app_controller.decrypt_choose_private_key_click(app))
        private_key_file_button.grid(row=0, column=0, pady=(10, 0))

        if private_key_file_path is not None:
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen private key:", font=("Courier new", 20))
                text_label.grid(row=1, column=0, pady=10, padx=(10, 5), sticky="ew")

                public_key_file_path_label = ctk.CTkLabel(master=self, text=private_key_file_path, fg_color="Green",
                                                          font=("Courier new", 20),
                                                          width=app.width * 0.5, height=app.height * 0.1)
                public_key_file_path_label.grid(row=2, column=0, pady=10, padx=(10, 5))

                encrypt_button = ctk.CTkButton(self, text="Decrypt file", font=("Courier new", 20), width=app.width * 0.5,
                                               height=app.height * 0.1,
                                               command=lambda: app_controller.decrypt_file_click(app, file_path=file_path,
                                                                                                 private_key_file_path=private_key_file_path))

                encrypt_button.grid(row=3, column=0, pady=10, padx=(10, 5))
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Courier new", 20),
                                          text_color="red")
                text_label.grid(row=1, column=0, pady=20, padx=(10, 5))

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width * 0.5,
                                      height=app.height * 0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=4, column=0, pady=(10, 10))
class ShowResultFrame(ctk.CTkFrame):
    def __init__(self, parent: any, app, result="", success=True, path=None):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2), weight=1)
        self.grid_columnconfigure(0, weight=1)

        if success:
            text_label = ctk.CTkLabel(master=self, text=result, font=("Courier new", 20), text_color="green")
            text_label.grid(row=1, column=0, pady=20, sticky="n")
        else:
            text_label = ctk.CTkLabel(master=self, text=result, font=("Courier new", 20), text_color="red")
            text_label.grid(row=1, column=0, pady=20, sticky="n")

        return_button = ctk.CTkButton(self, text="Return", font=("Courier new", 20), width=app.width * 0.5,
                                      height=app.height * 0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=2, column=0, pady=(10, 10))
