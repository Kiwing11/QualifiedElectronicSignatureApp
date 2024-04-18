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
        return_button = ctk.CTkButton(self, text="Return", width=app.width*0.5, height=app.height*0.2, command=lambda:  app.set_frame(MainFrame)).grid(row=1, column=0, pady=(10, 20))


class ExternalDevicesFrame(ctk.CTkFrame):
    def __init__(self, parent:  any, app, external_storage, pem_files):
        super().__init__(parent)
        self.pack(pady=20, padx=20, fill='both', expand=True)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)
        self.grid_columnconfigure(0, weight=1)

        (ctk.CTkLabel(master=self, width=app.width*0.5, height=app.height*0.2, text="Found external storage: " + external_storage[0], font=("Calibri", 20))
         .grid(row=0, column=0, pady=(10, 0), sticky="n"))

        if pem_files is None:
            (ctk.CTkLabel(master=self, width=app.width*0.5, height=app.height*0.2,  text="No .pem file found", font=("Calibri", 20))
             .grid(row=2, column=0,  pady=(10, 20), sticky="n"))
        else:
            combobox = ctk.CTkComboBox(master=self, values=pem_files, font=("Calibri", 20), width=app.width * 0.5,
                                       height=30)
            combobox.grid(row=2, column=0, padx=10, pady=(10, 20))
            combobox.set(pem_files[0])

        return_button = ctk.CTkButton(self, text="Return", width=app.width*0.5, height=app.height*0.2,  command=lambda: app.set_frame(MainFrame))
        return_button.grid(row=3, column=0, pady=(10, 20))
