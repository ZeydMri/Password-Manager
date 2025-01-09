import tkinter as tk
from tkinter import ttk, messagebox
import pyotp
from authenticator import Authenticator
from generator import Generator
from storage import Storage
from cryption import Cryption
import qrcode
from PIL import Image, ImageTk
import io


class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("SecretGuardian Password Manager")
        self.geometry("800x600")

        # Initialize components
        self.authenticator = None  # Will be initialized when needed
        self.storage = None  # Will be initialized when needed

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (HomePage, LoginPage, RegisterPage, PasswordGeneratorPage, PasswordVaultPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(HomePage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        label = ttk.Label(self, text="Welcome to SecretGuardian", font=("Helvetica", 24))
        label.pack(pady=50)

        ttk.Button(self, text="Login",
                   command=lambda: controller.show_frame(LoginPage)).pack(pady=10)
        ttk.Button(self, text="Register",
                   command=lambda: controller.show_frame(RegisterPage)).pack(pady=10)
        ttk.Button(self, text="Password Generator",
                   command=lambda: controller.show_frame(PasswordGeneratorPage)).pack(pady=10)


class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        ttk.Label(self, text="Login", font=("Helvetica", 20)).pack(pady=20)

        ttk.Label(self, text="Email:").pack()
        self.email = ttk.Entry(self)
        self.email.pack()

        ttk.Label(self, text="Password:").pack()
        self.password = ttk.Entry(self, show="*")
        self.password.pack()

        ttk.Label(self, text="2FA Code:").pack()
        self.otp = ttk.Entry(self)
        self.otp.pack()

        ttk.Button(self, text="Login", command=self.login).pack(pady=20)
        ttk.Button(self, text="Back",
                   command=lambda: controller.show_frame(HomePage)).pack()

    def login(self):
        # Initialize authenticator if needed
        if self.controller.authenticator is None:
            self.controller.authenticator = Authenticator()
            print("Initialized new authenticator")  # Debug print

        # Validate input fields
        email = self.email.get()
        password = self.password.get()
        otp = self.otp.get()

        if not email or not password or not otp:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        result = self.controller.authenticator.login(email, password, otp)
        print(f"Login result: {result}")  # Debug print

        if result == "Login successful.":
            self.controller.show_frame(PasswordVaultPage)
            self.email.delete(0, tk.END)
            self.password.delete(0, tk.END)
            self.otp.delete(0, tk.END)
        else:
            messagebox.showerror("Error", result)


class RegisterPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        ttk.Label(self, text="Register", font=("Helvetica", 20)).pack(pady=20)

        ttk.Label(self, text="Email:").pack()
        self.email = ttk.Entry(self)
        self.email.pack()

        ttk.Label(self, text="Password:").pack()
        self.password = ttk.Entry(self, show="*")
        self.password.pack()

        #self.controller.authenticator = Authenticator()
        email = self.email.get()
        password = self.password.get()

        ttk.Button(self, text="Register", command=self.register_user).pack(pady=20)
        ttk.Button(self, text="Back",
                   command=lambda: controller.show_frame(HomePage)).pack()

        self.qr_label = ttk.Label(self)
        self.qr_label.pack(pady=20)

    def register_user(self):
        # Initialize authenticator if needed
        if self.controller.authenticator is None:
            self.controller.authenticator = Authenticator()
            print("Initialized new authenticator")  # Debug print

        # Validate input fields
        email = self.email.get()
        password = self.password.get()

        if not email or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        qr_uri = self.controller.authenticator.register(email, password)
        print(f"Registration result: {qr_uri}")  # Debug print

        if not qr_uri.startswith("Email already registered") and not qr_uri.startswith("Invalid email"):
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=5,
                border=4,
            )
            qr.add_data(qr_uri)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")

            img_byte_arr = io.BytesIO()
            qr_image.save(img_byte_arr, format='PNG')
            img_byte_arr = img_byte_arr.getvalue()

            image = Image.open(io.BytesIO(img_byte_arr))
            photo = ImageTk.PhotoImage(image)

            self.qr_label.configure(image=photo)
            self.qr_label.image = photo

            messagebox.showinfo("Success",
                                "Account created! Scan the QR code with your authenticator app.")
        else:
            messagebox.showerror("Error", qr_uri)

class PasswordGeneratorPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        ttk.Label(self, text="Password Generator",
                  font=("Helvetica", 20)).pack(pady=20)

        ttk.Label(self, text="Password Length:").pack()
        self.length = ttk.Entry(self)
        self.length.insert(0, "12")
        self.length.pack()

        self.password_var = tk.StringVar()
        ttk.Label(self, textvariable=self.password_var).pack(pady=20)

        ttk.Button(self, text="Generate",
                   command=self.generate_password).pack(pady=10)
        ttk.Button(self, text="Copy to Clipboard",
                   command=self.copy_to_clipboard).pack(pady=10)
        ttk.Button(self, text="Back",
                   command=lambda: controller.show_frame(HomePage)).pack()

    def generate_password(self):
        try:
            length = int(self.length.get())
            generator = Generator("")
            password = generator.generate_password(length)
            self.password_var.set(password)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number.")

    def copy_to_clipboard(self):
        self.clipboard_clear()
        self.clipboard_append(self.password_var.get())
        messagebox.showinfo("Success", "Password copied to clipboard!")


class PasswordVaultPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.controller.storage = Storage()

        ttk.Label(self, text="Password Vault", font=("Helvetica", 20)).pack(pady=20)

        # Add new password section
        ttk.Label(self, text="Add New Password").pack()

        ttk.Label(self, text="Account:").pack()
        self.account = ttk.Entry(self)
        self.account.pack()

        ttk.Label(self, text="Password:").pack()
        self.password = ttk.Entry(self, show="*")
        self.password.pack()

        ttk.Button(self, text="Store Password", command=self.store_password).pack(pady=10)

        # Stored passwords section
        ttk.Label(self, text="Stored Passwords").pack(pady=20)

        self.passwords_listbox = tk.Listbox(self, width=50)
        self.passwords_listbox.pack(pady=10)

        ttk.Button(self, text="View Password", command=self.view_password).pack(pady=10)
        ttk.Button(self, text="Logout", command=lambda: controller.show_frame(HomePage)).pack()

        # Load stored passwords
        self.load_passwords()

    def store_password(self):
        account = self.account.get()
        password = self.password.get()

        if account and password:
            try:
                self.controller.storage.store(account, password)
                self.load_passwords()
                self.account.delete(0, tk.END)
                self.password.delete(0, tk.END)
                messagebox.showinfo("Success", "Password stored successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to store password: {str(e)}")
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

    def load_passwords(self):
        self.passwords_listbox.delete(0, tk.END)
        for account in self.controller.storage.data.keys():
            self.passwords_listbox.insert(tk.END, account)

    def view_password(self):
        selection = self.passwords_listbox.curselection()
        if selection:
            account = self.passwords_listbox.get(selection[0])
            try:
                decrypted_password = self.controller.storage.retrieve(account)
                messagebox.showinfo("Password", f"Password for {account}: {decrypted_password}")
            except KeyError:
                messagebox.showerror("Error", "No password found for this account.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to retrieve password: {str(e)}")
        else:
            messagebox.showerror("Error", "Please select an account.")


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()