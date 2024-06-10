import app_controller
import customtkinter as ctk


class MainFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2), weight=1)
        self.grid_columnconfigure(0, weight=1)

        sign_file_button = (ctk.CTkButton(self, text="Sign File", width=app.width*0.5, height=app.height*0.2, command=lambda: app_controller.sign_file_click(app))
                            .grid(row=0, column=0, pady=(10, 0)))

        encrypt_button = (ctk.CTkButton(self, text="Encrypt", width=app.width*0.5, height=app.height*0.2, command=lambda: app_controller.sign_file_click(app))
                          .grid(row=1, column=0, pady=(10, 0)))

        decrypt_button = (ctk.CTkButton(self, text="Decrypt", width=app.width*0.5, height=app.height*0.2)
                          .grid(row=2, column=0, pady=(10, 0)))



class NoExternalDevicesFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure( (0, 1), weight=1)
        self.grid_columnconfigure(0, weight=1)
        label = ctk.CTkLabel(self, text="No external storage found").grid(row=0, column=0, pady=(10, 0), sticky="n")
        return_button = (ctk.CTkButton(self, text="Return", width=app.width*0.5, height=app.height*0.2, command=lambda:  app.set_frame(MainFrame))
                         .grid(row=1, column=0, pady=(10, 20)))


class ExternalDevicesFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app, external_storage, pem_files, show_invalid_pin=False):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.grid_columnconfigure(0, weight=1)

        (ctk.CTkLabel(master=self, width=app.width*0.5, height=app.height*0.2, text="Found external storage: " + external_storage[0], font=("Calibri", 20))
         .grid(row=0, column=0, pady=(10, 0), sticky="n"))

        if pem_files is None:
            (ctk.CTkLabel(master=self, width=app.width*0.5, height=app.height*0.2,  text="No .pem file found", font=("Calibri", 20))
             .grid(row=2, column=0,  pady=(10, 20), sticky="n"))
        else:
            combobox = ctk.CTkComboBox(master=self, values=pem_files, font=("Calibri", 20), width=app.width * 0.5,
                                       height=15)
            combobox.grid(row=1, column=0, padx=10, pady=(10, 20))
            combobox.set(pem_files[0])

            if show_invalid_pin:
                (ctk.CTkLabel(master=self, width=app.width * 0.5, height=app.height*0.1, text="Invalid PIN",
                              font=("Calibri", 20), text_color="red")
                 .grid(row=3, column=0, pady=(0, 0), sticky="n"))

            pin_entry = ctk.CTkEntry(
                master=self, width=app.width * 0.5, height=30, font=("Calibri", 20), placeholder_text="Enter PIN",
                show="*"
            )
            pin_entry.grid(row=2, column=0, padx=10, pady=(0, 20))

            decrypt_button = ctk.CTkButton(self, text="Decrypt", width=app.width*0.5, height=app.height*0.1,
                                           command=lambda: app_controller.decrypt_click(app, combobox.get(), pin_entry.get(), external_storage, pem_files))
            decrypt_button.grid(row=4, column=0, pady=(10, 20))

        return_button = ctk.CTkButton(self, text="Return", width=app.width*0.5, height=app.height*0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=5, column=0, pady=(10, 20))

class SignFileFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app, file_path=None, valid_file_extension=True):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.grid_columnconfigure(0, weight=1)

        file_button = ctk.CTkButton(self, text="Choose File", font=("Calibri", 20), width=app.width*0.5, height=app.height*0.1,
                                    command=lambda: app_controller.choose_file_click(app))
        file_button.grid(row=0, column=0, pady=(10, 0))

        if file_path is not None:
            file_path_label = ctk.CTkLabel(master=self, text=file_path, fg_color="Green", font=("Calibri", 20), width=app.width*0.5, height=app.height*0.1)
            file_path_label.grid(row=3, column=0, pady=10, sticky="n")
            if valid_file_extension:
                text_label = ctk.CTkLabel(master=self, text="Chosen file:", font=("Calibri", 20))
                text_label.grid(row=2, column=0, pady=10, sticky="n")
                sign_button = ctk.CTkButton(self, text="Sign file", font=("Calibri", 20), width=app.width*0.5,
                                            height=app.height*0.1, command=lambda: app_controller.sign_click(app, file_path))
                sign_button.grid(row=4, column=0, pady=10, sticky="n")
            else:
                text_label = ctk.CTkLabel(master=self, text="Wrong file extension", font=("Calibri", 20),
                                          text_color="red")
                text_label.grid(row=2, column=0, pady=20, sticky="n")

        return_button = ctk.CTkButton(self, text="Return", font=("Calibri", 20), width=app.width*0.5, height=app.height*0.1,
                                      command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=5, column=0, pady=(10, 20))

