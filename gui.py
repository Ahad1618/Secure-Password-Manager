import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import time
import threading
from core import PasswordManager

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("600x700")
        self.root.resizable(False, False)
        
        self.manager = PasswordManager()
        self.current_username = None
        self.current_password = None
        self.otp_data = {"code": 0, "timestamp": 0, "validity": 0, "username": ""}  # Initialize as dictionary
        
        self.setup_style()
        self.show_login_page()
    
    def setup_style(self):
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#ccc")
        style.configure("TLabel", padding=6, font=('Helvetica', 10))
        style.configure("Header.TLabel", font=('Helvetica', 14, 'bold'))
        
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_page(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Password Manager Login", style="Header.TLabel").pack(pady=10)
        
        # Username
        ttk.Label(frame, text="Username:").pack(anchor="w", pady=(10, 0))
        username_var = tk.StringVar()
        username_entry = ttk.Entry(frame, textvariable=username_var, width=40)
        username_entry.pack(pady=(0, 10), fill="x")
        
        # Password
        ttk.Label(frame, text="Password:").pack(anchor="w")
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*", width=40)
        password_entry.pack(pady=(0, 20), fill="x")
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=10)
        
        ttk.Button(button_frame, text="Login", 
                   command=lambda: self.login(username_var.get(), password_var.get())
                  ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Sign Up", 
                   command=self.show_signup_page
                  ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Forgot Password", 
                   command=lambda: self.show_forgot_password_page(username_var.get())
                  ).pack(side=tk.LEFT, padx=5)
        
        username_entry.focus()
    
    def login(self, username, password):
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        if self.manager.findMasterCredentials(username, password):
            self.current_username = username
            self.current_password = password
            self.show_main_page()
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def show_signup_page(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Create an Account", style="Header.TLabel").pack(pady=10)
        
        # Username
        ttk.Label(frame, text="Username:").pack(anchor="w", pady=(10, 0))
        username_var = tk.StringVar()
        username_entry = ttk.Entry(frame, textvariable=username_var, width=40)
        username_entry.pack(pady=(0, 10), fill="x")
        
        # Email
        ttk.Label(frame, text="Email:").pack(anchor="w")
        email_var = tk.StringVar()
        email_entry = ttk.Entry(frame, textvariable=email_var, width=40)
        email_entry.pack(pady=(0, 10), fill="x")
        
        # Password
        ttk.Label(frame, text="Password:").pack(anchor="w")
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*", width=40)
        password_entry.pack(pady=(0, 10), fill="x")
        
        # Password strength indicator
        strength_var = tk.StringVar(value="Password Strength: Not evaluated")
        strength_label = ttk.Label(frame, textvariable=strength_var)
        strength_label.pack(anchor="w", pady=(0, 10))
        
        def check_strength():
            password = password_var.get()
            if password:
                strength = self.manager.passStrengthCheck(password)
                strength_var.set(f"Password Strength: {strength}")
        
        password_entry.bind("<KeyRelease>", lambda e: check_strength())
        
        # Confirm Password
        ttk.Label(frame, text="Confirm Password:").pack(anchor="w")
        confirm_password_var = tk.StringVar()
        confirm_password_entry = ttk.Entry(frame, textvariable=confirm_password_var, show="*", width=40)
        confirm_password_entry.pack(pady=(0, 10), fill="x")
        
        # Suggest password button
        def suggest_password():
            suggested_password = self.manager.passSuggest()
            password_var.set(suggested_password)
            confirm_password_var.set(suggested_password)
            check_strength()
        
        ttk.Button(frame, text="Suggest Password", command=suggest_password).pack(anchor="w", pady=(0, 10))
        
        # Sign Up Button
        def do_signup():
            username = username_var.get()
            email = email_var.get()
            password = password_var.get()
            confirm_password = confirm_password_var.get()
            
            if not username or not email or not password or not confirm_password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
                
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return
                
            strength = self.manager.passStrengthCheck(password)
            if strength == "Weak":
                if not messagebox.askyesno("Weak Password", 
                                           "Your password is weak. Do you want to continue anyway?"):
                    return
            
            result = self.manager.signup(username, email, password)
            messagebox.showinfo("Sign Up", result)
            if "successful" in result:
                self.show_login_page()
        
        ttk.Button(frame, text="Sign Up", command=do_signup).pack(pady=10, fill="x")
        ttk.Button(frame, text="Back to Login", command=self.show_login_page).pack(fill="x")
        
        username_entry.focus()
    
    def show_forgot_password_page(self, username=""):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Forgot Password", style="Header.TLabel").pack(pady=10)
        
        # Username
        ttk.Label(frame, text="Username:").pack(anchor="w", pady=(10, 0))
        username_var = tk.StringVar(value=username)
        username_entry = ttk.Entry(frame, textvariable=username_var, width=40)
        username_entry.pack(pady=(0, 10), fill="x")
        
        # Email
        ttk.Label(frame, text="Email:").pack(anchor="w")
        email_var = tk.StringVar()
        email_entry = ttk.Entry(frame, textvariable=email_var, width=40)
        email_entry.pack(pady=(0, 10), fill="x")
        
        # OTP Frame (initially hidden)
        otp_frame = ttk.Frame(frame)
        otp_var = tk.StringVar()
        otp_label = ttk.Label(otp_frame, text="Enter OTP sent to your email:")
        otp_entry = ttk.Entry(otp_frame, textvariable=otp_var, width=10)
        timer_label = ttk.Label(otp_frame, text="Time remaining: 50s")
        
        # Countdown timer for OTP
        def start_timer(duration=50):
            end_time = time.time() + duration
            
            def update_timer():
                remaining = int(end_time - time.time())
                if remaining > 0:
                    timer_label.config(text=f"Time remaining: {remaining}s")
                    self.root.after(1000, update_timer)
                else:
                    timer_label.config(text="OTP expired!")
            
            update_timer()
        
        # Send OTP function
        def send_otp():
            username = username_var.get()
            email = email_var.get()
            
            if not username or not email:
                messagebox.showerror("Error", "Please enter both username and email")
                return
                
            # Check if username exists and email matches
            user_email = self.manager.getUserEmail(username)
            if not user_email or user_email != email:
                messagebox.showerror("Error", "Username or email not found")
                return
                
            # Generate and send OTP
            otp_code = self.manager.generate_otp()
            
            # Show OTP components
            otp_label.pack(anchor="w", pady=(10, 0))
            otp_entry.pack(anchor="w", pady=(5, 0))
            timer_label.pack(anchor="w", pady=(5, 10))
            otp_frame.pack(fill="x")
            
            # Start the countdown timer
            start_timer()
            
            # Store OTP and timestamp
            self.otp_data = {
                "code": otp_code,
                "timestamp": time.time(),
                "validity": 50,  # 50 seconds validity
                "username": username
            }
            
            # Send email with OTP
            email_subject = "Your OTP for Secure Password Manager Access"
            email_body = f"""
Hello,

We have generated an OTP for your account in the Password Manager. Please use this OTP to access your account and update it as soon as possible.

***** OTP CODE:  {otp_code} *****This OTP will expire in 50 seconds******

For security reasons, please do not share this OTP with anyone, and make sure to change it to something more secure after logging in.

If you did not request this temporary password, please contact our support team immediately.

Best regards,
The Password Manager Team
"""
            t = threading.Thread(target=lambda: self.manager.send_email(email_subject, email_body, email))
            t.start()
            messagebox.showinfo("OTP Sent", "OTP has been sent to your email")
            
        # Verify OTP function
        def verify_otp():
            entered_otp = otp_var.get()
            
            if not entered_otp:
                messagebox.showerror("Error", "Please enter the OTP")
                return
                
            try:
                entered_otp = int(entered_otp)
            except ValueError:
                messagebox.showerror("Error", "OTP must be a number")
                return
                
            # Check if OTP is valid and not expired
            current_time = time.time()
            elapsed_time = current_time - self.otp_data["timestamp"]
            
            if elapsed_time > self.otp_data["validity"]:
                messagebox.showerror("Error", "OTP has expired. Please request a new one.")
                return
                
            if entered_otp != self.otp_data["code"]:
                messagebox.showerror("Error", "Invalid OTP")
                return
                
            # OTP verified, show reset password screen
            self.show_reset_password_screen(self.otp_data["username"])
        
        # Send OTP button
        ttk.Button(frame, text="Send OTP", command=send_otp).pack(pady=10)
        
        # Verify OTP button
        ttk.Button(otp_frame, text="Verify OTP", command=verify_otp).pack(pady=10)
        
        # Back button
        ttk.Button(frame, text="Back to Login", command=self.show_login_page).pack(fill="x", pady=(10, 0))
        
        otp_frame.pack_forget()  # Initially hidden
        
        username_entry.focus()
    
    def show_reset_password_screen(self, username):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Reset Master Password", style="Header.TLabel").pack(pady=10)
        ttk.Label(frame, text=f"Username: {username}").pack(anchor="w", pady=(10, 0))
        
        # New Password
        ttk.Label(frame, text="New Password:").pack(anchor="w", pady=(10, 0))
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*", width=40)
        password_entry.pack(pady=(0, 10), fill="x")
        
        # Password strength indicator
        strength_var = tk.StringVar(value="Password Strength: Not evaluated")
        strength_label = ttk.Label(frame, textvariable=strength_var)
        strength_label.pack(anchor="w", pady=(0, 10))
        
        def check_strength():
            password = password_var.get()
            if password:
                strength = self.manager.passStrengthCheck(password)
                strength_var.set(f"Password Strength: {strength}")
        
        password_entry.bind("<KeyRelease>", lambda e: check_strength())
        
        # Confirm Password
        ttk.Label(frame, text="Confirm Password:").pack(anchor="w")
        confirm_password_var = tk.StringVar()
        confirm_password_entry = ttk.Entry(frame, textvariable=confirm_password_var, show="*", width=40)
        confirm_password_entry.pack(pady=(0, 10), fill="x")
        
        # Suggest password button
        def suggest_password():
            suggested_password = self.manager.passSuggest()
            password_var.set(suggested_password)
            confirm_password_var.set(suggested_password)
            check_strength()
        
        ttk.Button(frame, text="Suggest Password", command=suggest_password).pack(anchor="w", pady=(0, 10))
        
        # Reset Password Button
        def do_reset():
            password = password_var.get()
            confirm_password = confirm_password_var.get()
            
            if not password or not confirm_password:
                messagebox.showerror("Error", "Please enter both fields")
                return
                
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return
                
            strength = self.manager.passStrengthCheck(password)
            if strength == "Weak":
                if not messagebox.askyesno("Weak Password", 
                                           "Your password is weak. Do you want to continue anyway?"):
                    return
            
            result = self.manager.resetMasterPassword(username, password)
            messagebox.showinfo("Password Reset", result)
            self.show_login_page()
        
        ttk.Button(frame, text="Reset Password", command=do_reset).pack(pady=10, fill="x")
        ttk.Button(frame, text="Cancel", command=self.show_login_page).pack(fill="x")
        
        password_entry.focus()
    
    def show_main_page(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=f"Welcome, {self.current_username}!", style="Header.TLabel").pack(pady=10)
        
        # Search bar
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5, fill="x", expand=True)
        
        def search_accounts():
            search_term = search_var.get().lower()
            # Refresh the account list with the search filter
            refresh_accounts(search_term)
            
        ttk.Button(search_frame, text="Search", command=search_accounts).pack(side=tk.LEFT)
        ttk.Button(search_frame, text="Clear", 
                  command=lambda: [search_var.set(""), refresh_accounts()]
                  ).pack(side=tk.LEFT, padx=5)
        
        # Create a frame for accounts display
        accounts_frame = ttk.LabelFrame(frame, text="Your Accounts")
        accounts_frame.pack(fill="both", expand=True, pady=10)
        
        # Create scrollable area for accounts
        canvas = tk.Canvas(accounts_frame)
        scrollbar = ttk.Scrollbar(accounts_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Function to refresh accounts list
        def refresh_accounts(search_term=""):
            # Clear previous accounts
            for widget in scrollable_frame.winfo_children():
                widget.destroy()
                
            # Get accounts for current user
            accounts = self.manager.getAccounts(self.current_username)
            
            # Filter accounts if search term is provided
            if search_term:
                accounts = [acc for acc in accounts if search_term in acc['id'].lower()]
            
            if not accounts:
                ttk.Label(scrollable_frame, text="No accounts saved yet").pack(pady=10)
            else:
                # Display each account
                for account in accounts:
                    account_frame = ttk.Frame(scrollable_frame)
                    account_frame.pack(fill="x", pady=2)
                    
                    ttk.Label(account_frame, text=f"{account['index']}: {account['id']}").pack(side="left")
                    
                    # Buttons for account actions
                    ttk.Button(account_frame, text="Copy Password", 
                              command=lambda idx=account['index']: self.copy_password(idx)
                              ).pack(side="right", padx=2)
                    
                    ttk.Button(account_frame, text="Modify", 
                              command=lambda idx=account['index']: self.modify_account(idx)
                              ).pack(side="right", padx=2)
                    
                    ttk.Button(account_frame, text="Remove", 
                              command=lambda idx=account['index']: self.remove_account(idx, lambda: refresh_accounts(search_term))
                              ).pack(side="right", padx=2)
        
        # Initial account list loading
        refresh_accounts()
        
        # Button frame for main actions
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=10)
        
        ttk.Button(button_frame, text="Add Account", 
                   command=lambda: self.add_account(refresh_accounts)
                  ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Reset Master Password", 
                   command=self.reset_master_password
                  ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Export Backup", 
                   command=self.export_backup
                  ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Help", 
                   command=self.show_help
                  ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Logout", 
                   command=self.logout
                  ).pack(side=tk.RIGHT, padx=5)
    
    def copy_password(self, account_index):
        password = self.manager.retrievePass(self.current_username, self.current_password, account_index)
        if password:
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showerror("Error", "Could not retrieve password")
    
    def add_account(self, refresh_callback):
        # Create a dialog for adding an account
        add_window = tk.Toplevel(self.root)
        add_window.title("Add Account")
        add_window.geometry("400x450")  # Increased height from 350 to 450
        add_window.resizable(False, False)
        add_window.transient(self.root)
        add_window.grab_set()
        
        frame = ttk.Frame(add_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Add New Account", style="Header.TLabel").pack(pady=10)
        
        # Account ID
        ttk.Label(frame, text="Account ID:").pack(anchor="w", pady=(10, 0))
        account_id_var = tk.StringVar()
        account_id_entry = ttk.Entry(frame, textvariable=account_id_var, width=40)
        account_id_entry.pack(pady=(0, 10), fill="x")
        
        # Password
        ttk.Label(frame, text="Password:").pack(anchor="w")
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*", width=40)
        password_entry.pack(pady=(0, 10), fill="x")
        
        # Password strength indicator
        strength_var = tk.StringVar(value="Password Strength: Not evaluated")
        strength_label = ttk.Label(frame, textvariable=strength_var)
        strength_label.pack(anchor="w", pady=(0, 10))
        
        def check_strength():
            password = password_var.get()
            if password:
                strength = self.manager.passStrengthCheck(password)
                strength_var.set(f"Password Strength: {strength}")
        
        password_entry.bind("<KeyRelease>", lambda e: check_strength())
        
        # Suggest password button
        def suggest_password():
            suggested_password = self.manager.passSuggest()
            password_var.set(suggested_password)
            check_strength()
        
        ttk.Button(frame, text="Suggest Password", command=suggest_password).pack(anchor="w", pady=(0, 10))
        
        # Add Account Button
        def do_add_account():
            account_id = account_id_var.get()
            password = password_var.get()
            
            if not account_id or not password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
                
            result = self.manager.addAcc(self.current_username, self.current_password, account_id, password)
            messagebox.showinfo("Add Account", result)
            
            if "successfully" in result:
                add_window.destroy()
                refresh_callback()
        
        ttk.Button(frame, text="Add Account", command=do_add_account).pack(pady=10, fill="x")
        ttk.Button(frame, text="Cancel", command=add_window.destroy).pack(fill="x")
        
        account_id_entry.focus()
    
    def modify_account(self, account_index):
        # Get account details
        accounts = self.manager.getAccounts(self.current_username)
        selected_account = next((acc for acc in accounts if acc['index'] == account_index), None)
        
        if not selected_account:
            messagebox.showerror("Error", "Account not found")
            return
        
        # Create a dialog for modifying the account
        modify_window = tk.Toplevel(self.root)
        modify_window.title("Modify Account")
        modify_window.geometry("400x350")
        modify_window.resizable(False, False)
        modify_window.transient(self.root)
        modify_window.grab_set()
        
        frame = ttk.Frame(modify_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=f"Modify Account: {selected_account['id']}", style="Header.TLabel").pack(pady=10)
        
        # New Password
        ttk.Label(frame, text="New Password:").pack(anchor="w", pady=(10, 0))
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*", width=40)
        password_entry.pack(pady=(0, 10), fill="x")
        
        # Password strength indicator
        strength_var = tk.StringVar(value="Password Strength: Not evaluated")
        strength_label = ttk.Label(frame, textvariable=strength_var)
        strength_label.pack(anchor="w", pady=(0, 10))
        
        def check_strength():
            password = password_var.get()
            if password:
                strength = self.manager.passStrengthCheck(password)
                strength_var.set(f"Password Strength: {strength}")
        
        password_entry.bind("<KeyRelease>", lambda e: check_strength())
        
        # Suggest password button
        def suggest_password():
            suggested_password = self.manager.passSuggest()
            password_var.set(suggested_password)
            check_strength()
        
        ttk.Button(frame, text="Suggest Password", command=suggest_password).pack(anchor="w", pady=(0, 10))
        
        # Modify Account Button
        def do_modify_account():
            new_password = password_var.get()
            
            if not new_password:
                messagebox.showerror("Error", "Please enter a new password")
                return
                
            result = self.manager.modifyPass(self.current_username, self.current_password, 
                                            account_index, new_password)
            messagebox.showinfo("Modify Account", result)
            
            if "successfully" in result:
                modify_window.destroy()
        
        ttk.Button(frame, text="Update Password", command=do_modify_account).pack(pady=10, fill="x")
        ttk.Button(frame, text="Cancel", command=modify_window.destroy).pack(fill="x")
        
        password_entry.focus()
    
    def remove_account(self, account_index, refresh_callback):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this account?"):
            result = self.manager.removeAcc(self.current_username, account_index)
            messagebox.showinfo("Remove Account", result)
            refresh_callback()
    
    def reset_master_password(self):
        # Create a dialog for resetting master password
        reset_window = tk.Toplevel(self.root)
        reset_window.title("Reset Master Password")
        reset_window.geometry("400x350")
        reset_window.resizable(False, False)
        reset_window.transient(self.root)
        reset_window.grab_set()
        
        frame = ttk.Frame(reset_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Reset Master Password", style="Header.TLabel").pack(pady=10)
        
        # New Password
        ttk.Label(frame, text="New Password:").pack(anchor="w", pady=(10, 0))
        password_var = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*", width=40)
        password_entry.pack(pady=(0, 10), fill="x")
        
        # Password strength indicator
        strength_var = tk.StringVar(value="Password Strength: Not evaluated")
        strength_label = ttk.Label(frame, textvariable=strength_var)
        strength_label.pack(anchor="w", pady=(0, 10))
        
        def check_strength():
            password = password_var.get()
            if password:
                strength = self.manager.passStrengthCheck(password)
                strength_var.set(f"Password Strength: {strength}")
        
        password_entry.bind("<KeyRelease>", lambda e: check_strength())
        
        # Confirm Password
        ttk.Label(frame, text="Confirm Password:").pack(anchor="w")
        confirm_password_var = tk.StringVar()
        confirm_password_entry = ttk.Entry(frame, textvariable=confirm_password_var, show="*", width=40)
        confirm_password_entry.pack(pady=(0, 10), fill="x")
        
        # Suggest password button
        def suggest_password():
            suggested_password = self.manager.passSuggest()
            password_var.set(suggested_password)
            confirm_password_var.set(suggested_password)
            check_strength()
        
        ttk.Button(frame, text="Suggest Password", command=suggest_password).pack(anchor="w", pady=(0, 10))
        
        # Reset Button
        def do_reset():
            new_password = password_var.get()
            confirm_password = confirm_password_var.get()
            
            if not new_password or not confirm_password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
                
            if new_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            result = self.manager.resetMasterPassword(self.current_username, new_password)
            messagebox.showinfo("Reset Master Password", result)
            
            # Update current password and close window
            self.current_password = new_password
            reset_window.destroy()
        
        ttk.Button(frame, text="Reset Password", command=do_reset).pack(pady=10, fill="x")
        ttk.Button(frame, text="Cancel", command=reset_window.destroy).pack(fill="x")
        
        password_entry.focus()
    
    def logout(self):
        self.current_username = None
        self.current_password = None
        self.show_login_page()
    
    def export_backup(self):
        try:
            import datetime
            current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"password_manager_backup_{current_time}.json"
            
            with open(backup_filename, "w") as backup_file:
                with open("database2.json", "r") as original_file:
                    backup_file.write(original_file.read())
            
            messagebox.showinfo("Backup Created", f"A backup has been created as '{backup_filename}'")
        except Exception as e:
            messagebox.showerror("Backup Failed", f"Could not create backup: {str(e)}")
    
    def show_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Password Manager Help")
        help_window.geometry("500x500")
        help_window.resizable(False, False)
        help_window.transient(self.root)
        help_window.grab_set()
        
        frame = ttk.Frame(help_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Password Manager Help", style="Header.TLabel").pack(pady=10)
        
        help_text = """
• Add Account: Add a new account to your password manager
• Modify: Change the password for an existing account
• Remove: Delete an account from your password manager
• Copy Password: Copy an account password to clipboard
• Reset Master Password: Change your master password
• Export Backup: Create a backup of your password database
• Search: Find accounts by their ID/name
• Logout: Exit to the login screen

Password Strength Tips:
• Use at least 12 characters
• Include uppercase and lowercase letters
• Include numbers and special characters
• Avoid common words or patterns
        """
        
        text_widget = tk.Text(frame, wrap="word", height=15, width=50)
        text_widget.insert("1.0", help_text)
        text_widget.config(state="disabled")
        text_widget.pack(pady=10, fill="both", expand=True)
        
        ttk.Button(frame, text="Close", command=help_window.destroy).pack(pady=10) 