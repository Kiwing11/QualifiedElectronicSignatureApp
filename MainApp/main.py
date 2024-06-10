import customtkinter as  ctk
import app_controller
from frames import *
from tkinter import filedialog


class App(ctk.CTk):
    width = 600
    height = 400
    frame = None

    def __init__(self):
        super().__init__()
        self.title('Qualified Electronic Signature App')
        self.geometry(f"{self.width}x{self.height}")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.set_frame(MainFrame)

    def set_frame(self, frame, *args, **kwargs):
        if self.frame is not None:
            self.frame.pack_forget()

        self.frame = frame(self, self, *args, **kwargs)


app = App()
app.mainloop()
