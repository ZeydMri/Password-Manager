import customtkinter as ctk
from tkinter import messagebox
import tkinter as tk
from authenticator import Authenticator
from generator import Generator
from storage import Storage
import qrcode
from PIL import Image, ImageTk
import io
from email_services import EmailService


class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Set the theme and color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("SecretGuardian Password Manager")
        self.geometry("900x700")

        # Initialize components
        self.authenticator = None
        self.storage = None

        container = ctk.CTkFrame(self)
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


class HomePage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        ctk.CTkFrame.__init__(self, parent)
        self.controller = controller

        # Create main container with padding
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(expand=True, fill="both", padx=20, pady=20)

        # Welcome label with custom styling
        label = ctk.CTkLabel(
            main_container,
            text="Welcome to SecretGuardian",
            font=ctk.CTkFont(size=32, weight="bold")
        )
        label.pack(pady=50)

        # Create a canvas for the shield and key logo
        canvas = tk.Canvas(
            main_container,
            width=160,
            height=180,
            bg='#2b2b2b',
            highlightthickness=0
        )
        canvas.pack(pady=(0, 30))

        # Draw shield (basic polygon)
        shield_coords = [
            80, 20,  # Top point
            140, 40,  # Top right
            140, 120,  # Bottom right
            80, 150,  # Bottom point
            20, 120,  # Bottom left
            20, 40  # Top left
        ]

        # Shield base
        canvas.create_polygon(
            shield_coords,
            fill="#1f538d",
            outline="#3a7fc6",
            width=3
        )

        # Draw centered key
        # Key head (ring)
        canvas.create_oval(
            65, 50,  # Top left
            95, 80,  # Bottom right
            fill="#2a6fb6",
            outline="#3a7fc6",
            width=2
        )

        # Key inner ring detail
        canvas.create_oval(
            70, 55,  # Top left
            90, 75,  # Bottom right
            fill="#1f538d",
            outline="#3a7fc6",
            width=1
        )

        # Key shaft
        canvas.create_rectangle(
            78, 75,  # Top left
            82, 130,  # Bottom right
            fill="#2a6fb6",
            outline="#3a7fc6",
            width=1
        )

        # Key teeth
        teeth_coords = [
            (82, 110), (90, 110),  # First tooth
            (90, 115), (82, 115),  # Back to shaft
            (82, 115), (88, 115),  # Second tooth
            (88, 120), (82, 120),  # Back to shaft
            (82, 120), (92, 120),  # Third tooth
            (92, 125), (82, 125),  # Back to shaft
            (82, 125), (86, 125),  # Fourth tooth
            (86, 130), (78, 130)  # Back to shaft
        ]
        canvas.create_polygon(
            teeth_coords,
            fill="#2a6fb6",
            outline="#3a7fc6",
            width=1
        )

        # Add app name
        canvas.create_text(
            80, 165,
            text="SecretGuardian",
            fill="#3a7fc6",
            font=("Helvetica", 16, "bold")
        )

        # Button container for better organization
        button_container = ctk.CTkFrame(main_container, fg_color="transparent")
        button_container.pack(expand=True)

        # Styled buttons with hover effect
        ctk.CTkButton(
            button_container,
            text="Login",
            font=ctk.CTkFont(size=16),
            width=200,
            height=40,
            corner_radius=8,
            command=lambda: controller.show_frame(LoginPage)
        ).pack(pady=10)

        ctk.CTkButton(
            button_container,
            text="Register",
            font=ctk.CTkFont(size=16),
            width=200,
            height=40,
            corner_radius=8,
            command=lambda: controller.show_frame(RegisterPage)
        ).pack(pady=10)

        ctk.CTkButton(
            button_container,
            text="Password Generator",
            font=ctk.CTkFont(size=16),
            width=200,
            height=40,
            corner_radius=8,
            command=lambda: controller.show_frame(PasswordGeneratorPage)
        ).pack(pady=10)


class LoginPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        ctk.CTkFrame.__init__(self, parent)
        self.controller = controller

        # Main container
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(expand=True, fill="both", padx=30, pady=30)

        # Header
        ctk.CTkLabel(
            main_container,
            text="Login",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=20)

        # Form container
        form_container = ctk.CTkFrame(main_container, fg_color="transparent")
        form_container.pack(pady=20)

        # Email field
        ctk.CTkLabel(
            form_container,
            text="Email:",
            font=ctk.CTkFont(size=14)
        ).pack()
        self.email = ctk.CTkEntry(
            form_container,
            width=300,
            height=40,
            placeholder_text="Enter your email"
        )
        self.email.pack(pady=(0, 15))

        # Password field
        ctk.CTkLabel(
            form_container,
            text="Password:",
            font=ctk.CTkFont(size=14)
        ).pack()
        self.password = ctk.CTkEntry(
            form_container,
            width=300,
            height=40,
            show="•",
            placeholder_text="Enter your password"
        )
        self.password.pack(pady=(0, 15))

        # 2FA field
        ctk.CTkLabel(
            form_container,
            text="2FA Code:",
            font=ctk.CTkFont(size=14)
        ).pack()
        self.otp = ctk.CTkEntry(
            form_container,
            width=300,
            height=40,
            placeholder_text="Enter 2FA code"
        )
        self.otp.pack(pady=(0, 20))

        # Buttons
        ctk.CTkButton(
            form_container,
            text="Login",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            command=self.login
        ).pack(pady=10)

        ctk.CTkButton(
            form_container,
            text="Back",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            fg_color="transparent",
            border_width=2,
            command=lambda: controller.show_frame(HomePage)
        ).pack()

    def login(self):
        if self.controller.authenticator is None:
            self.controller.authenticator = Authenticator()

        email = self.email.get()
        password = self.password.get()
        otp = self.otp.get()

        if not email or not password or not otp:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        result = self.controller.authenticator.login(email, password, otp)

        if result == "Login successful.":
            self.controller.show_frame(PasswordVaultPage)
            self.email.delete(0, ctk.END)
            self.password.delete(0, ctk.END)
            self.otp.delete(0, ctk.END)
        elif result == "Suspicious login detected. Additional verification required.":
            # Create email service if not exists
            if not hasattr(self.controller, 'email_service'):
                self.controller.email_service = EmailService()

            # Show verification window
            verification_window = VerificationWindow(self, self.controller.email_service, email)
            self.wait_window(verification_window)

            # Check verification result
            if verification_window.result:
                self.controller.show_frame(PasswordVaultPage)
                self.email.delete(0, ctk.END)
                self.password.delete(0, ctk.END)
                self.otp.delete(0, ctk.END)
            else:
                messagebox.showerror("Error", "Verification failed")
        else:
            messagebox.showerror("Error", result)


class RegisterPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        ctk.CTkFrame.__init__(self, parent)
        self.controller = controller

        # Main container
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(expand=True, fill="both", padx=30, pady=30)

        # Header
        ctk.CTkLabel(
            main_container,
            text="Register",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=20)

        # Form container
        form_container = ctk.CTkFrame(main_container, fg_color="transparent")
        form_container.pack(pady=20)

        # Email field
        ctk.CTkLabel(
            form_container,
            text="Email:",
            font=ctk.CTkFont(size=14)
        ).pack()
        self.email = ctk.CTkEntry(
            form_container,
            width=300,
            height=40,
            placeholder_text="Enter your email"
        )
        self.email.pack(pady=(0, 15))

        # Password field
        ctk.CTkLabel(
            form_container,
            text="Password:",
            font=ctk.CTkFont(size=14)
        ).pack()
        self.password = ctk.CTkEntry(
            form_container,
            width=300,
            height=40,
            show="•",
            placeholder_text="Enter your password"
        )
        self.password.pack(pady=(0, 20))

        # Buttons
        ctk.CTkButton(
            form_container,
            text="Register",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            command=self.register_user
        ).pack(pady=10)

        ctk.CTkButton(
            form_container,
            text="Back",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            fg_color="transparent",
            border_width=2,
            command=lambda: controller.show_frame(HomePage)
        ).pack()

        # QR code label
        self.qr_label = ctk.CTkLabel(form_container, text="")
        self.qr_label.pack(pady=20)

    def register_user(self):
        if self.controller.authenticator is None:
            self.controller.authenticator = Authenticator()

        email = self.email.get()
        password = self.password.get()

        if not email or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        qr_uri = self.controller.authenticator.register(email, password)

        if not qr_uri.startswith("Email already registered") and not qr_uri.startswith("Invalid email"):
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

            messagebox.showinfo("Success", "Account created! Scan the QR code with your authenticator app.")
        else:
            messagebox.showerror("Error", qr_uri)


class PasswordGeneratorPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        ctk.CTkFrame.__init__(self, parent)
        self.controller = controller

        # Main container
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(expand=True, fill="both", padx=30, pady=30)

        # Header
        ctk.CTkLabel(
            main_container,
            text="Password Generator",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=20)

        # Content container
        content_container = ctk.CTkFrame(main_container, fg_color="transparent")
        content_container.pack(pady=20)

        # Length input
        ctk.CTkLabel(
            content_container,
            text="Password Length:",
            font=ctk.CTkFont(size=14)
        ).pack()

        self.length = ctk.CTkEntry(
            content_container,
            width=200,
            height=40,
            placeholder_text="Enter length"
        )
        self.length.insert(0, "12")
        self.length.pack(pady=(0, 20))

        # Generated password display
        self.password_var = ctk.StringVar()
        self.password_display = ctk.CTkLabel(
            content_container,
            textvariable=self.password_var,
            font=ctk.CTkFont(size=16)
        )
        self.password_display.pack(pady=20)

        # Buttons
        ctk.CTkButton(
            content_container,
            text="Generate Password",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            command=self.generate_password
        ).pack(pady=10)

        ctk.CTkButton(
            content_container,
            text="Copy to Clipboard",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            command=self.copy_to_clipboard
        ).pack(pady=10)

        ctk.CTkButton(
            content_container,
            text="Back",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            fg_color="transparent",
            border_width=2,
            command=lambda: controller.show_frame(HomePage)
        ).pack(pady=10)

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


class PasswordVaultPage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        ctk.CTkFrame.__init__(self, parent)
        self.controller = controller
        self.controller.storage = Storage()

        # Main container
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(expand=True, fill="both", padx=30, pady=30)

        # Header
        ctk.CTkLabel(
            main_container,
            text="Password Vault",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=20)

        # Add password section
        add_section = ctk.CTkFrame(main_container)
        add_section.pack(pady=20, fill="x", padx=20)

        ctk.CTkLabel(
            add_section,
            text="Add New Password",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=10)

        # Account field
        ctk.CTkLabel(
            add_section,
            text="Account:",
            font=ctk.CTkFont(size=14)
        ).pack()
        self.account = ctk.CTkEntry(
            add_section,
            width=300,
            height=40,
            placeholder_text="Enter account name"
        )
        self.account.pack(pady=(0, 15))

        # Password field
        ctk.CTkLabel(
            add_section,
            text="Password:",
            font=ctk.CTkFont(size=14)
        ).pack()
        self.password = ctk.CTkEntry(
            add_section,
            width=300,
            height=40,
            show="•",
            placeholder_text="Enter password"
        )
        self.password.pack(pady=(0, 15))

        # Store button
        ctk.CTkButton(
            add_section,
            text="Store Password",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            command=self.store_password
        ).pack(pady=10)

        # Stored passwords section
        stored_section = ctk.CTkFrame(main_container)
        stored_section.pack(pady=20, fill="both", expand=True, padx=20)

        ctk.CTkLabel(
            stored_section,
            text="Stored Passwords",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=10)

        # Using regular Listbox since CTkListbox is not available
        # We'll style it to match the theme
        self.passwords_listbox = tk.Listbox(
            stored_section,
            width=50,
            height=10,
            font=("Helvetica", 12),
            bg="#2b2b2b",
            fg="white",
            selectmode="single",
            relief="flat",
            borderwidth=0
        )
        self.passwords_listbox.pack(pady=10, fill="both", expand=True)

        # Buttons container
        button_container = ctk.CTkFrame(stored_section, fg_color="transparent")
        button_container.pack(pady=10)

        ctk.CTkButton(
            button_container,
            text="View Password",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            command=self.view_password
        ).pack(pady=5)

        ctk.CTkButton(
            button_container,
            text="Logout",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            corner_radius=8,
            fg_color="#D22B2B",
            hover_color="#AA0000",
            command=lambda: controller.show_frame(HomePage)
        ).pack(pady=5)

        # Load stored passwords
        self.load_passwords()

    def store_password(self):
        account = self.account.get()
        password = self.password.get()

        if account and password:
            try:
                self.controller.storage.store(account, password)
                self.load_passwords()
                self.account.delete(0, ctk.END)
                self.password.delete(0, ctk.END)
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


class VerificationWindow(ctk.CTkToplevel):
    def __init__(self, parent, email_service, user_email):
        super().__init__(parent)
        self.email_service = email_service
        self.user_email = user_email
        self.verification_code = self.generate_verification_code()
        self.result = False

        # Window setup
        self.title("Login Verification")
        self.geometry("400x300")

        # Center the window
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

        # Create main container
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(expand=True, fill="both", padx=20, pady=20)

        # Add widgets
        ctk.CTkLabel(
            main_container,
            text="Additional Verification Required",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(0, 20))

        ctk.CTkLabel(
            main_container,
            text="We've detected a suspicious login attempt.\nPlease check your email for a verification code.",
            font=ctk.CTkFont(size=14),
            justify="center"
        ).pack(pady=(0, 20))

        # Code entry
        self.code_entry = ctk.CTkEntry(
            main_container,
            width=200,
            height=40,
            placeholder_text="Enter verification code"
        )
        self.code_entry.pack(pady=(0, 20))

        # Verify button
        ctk.CTkButton(
            main_container,
            text="Verify",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            command=self.verify_code
        ).pack(pady=(0, 10))

        # Resend button
        ctk.CTkButton(
            main_container,
            text="Resend Code",
            font=ctk.CTkFont(size=15),
            width=200,
            height=40,
            fg_color="transparent",
            border_width=2,
            command=self.resend_code
        ).pack()

        # Send initial verification code
        self.send_code()

    def generate_verification_code(self):
        """Generate a 6-digit verification code"""
        import random
        return str(random.randint(100000, 999999))

    def send_code(self):
        """Send the verification code to user's email"""
        self.email_service.send_verification_code(self.user_email, self.verification_code)

    def resend_code(self):
        """Generate and send a new verification code"""
        self.verification_code = self.generate_verification_code()
        self.send_code()
        messagebox.showinfo("Code Sent", "A new verification code has been sent to your email.")

    def verify_code(self):
        """Verify the entered code"""
        entered_code = self.code_entry.get()
        if entered_code == self.verification_code:
            self.result = True
            self.destroy()
        else:
            messagebox.showerror("Error", "Invalid verification code. Please try again.")
            self.code_entry.delete(0, ctk.END)