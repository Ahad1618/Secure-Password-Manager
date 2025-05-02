import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import json
import time
import random
import sys
import re
import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode, b64encode, urlsafe_b64encode, urlsafe_b64decode

class PasswordManager:
    def __init__(self):
        try:
            with open("database2.json", "r") as file:
                self.accs = json.loads(file.read())
        except FileNotFoundError:
            self.accs = {}
            self.save_data("database2.json", self.accs)
            
    def load_data(self, filename):
        try:
            with open(filename, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def save_data(self, filename, data):
        with open(filename, "w") as file:
            file.write(json.dumps(data, indent=4))
            self.accs = data 

    def send_email(self, subject, body, to_email):
        # Email configuration
        from_email = "ahadahadansari8@gmail.com"  #email address of the sender
        password = "shyh jvci glnc muah"     
        
        # Set up the MIME
        message = MIMEMultipart()
        message['From'] = from_email
        message['To'] = to_email
        message['Subject'] = subject
        
        # Add the email body to the message
        message.attach(MIMEText(body, 'plain'))
        
        server = None
        try:
            # Set up the server
            server = smtplib.SMTP("smtp.gmail.com", 587)  # Gmail SMTP server and port
            server.starttls()                             # Enable security (TLS)
            server.login(from_email, password)            # Log in to the email account
            
            # Send the email
            server.sendmail(from_email, to_email, message.as_string())
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
        finally:
            if server:
                server.quit()  # Close the server connection

    def generate_otp(self):
        return random.randint(100, 1000)
        
    def derive_key(self, password, salt):
        # Derives an AES key from the password and salt.
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_password(self, password, key):
        iv = os.urandom(12)  # AES-GCM requires a 12-byte IV
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()
        return iv, encrypted_password, encryptor.tag
    
    def passSuggest(self):
        length = 12  # Recommended minimum length for strong passwords
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lower = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        special = "!@#$%^&*()-_=+[]|;:'\",.<>?/`~"
        
        # Ensure the password has at least one of each type of character
        password = (
            random.choice(upper) +
            random.choice(lower) +
            random.choice(digits) +
            random.choice(special)
        )
        
        # Fill the rest of the password length with a mix of all character types
        all_characters = upper + lower + digits + special
        password += ''.join(random.choices(all_characters, k=length - len(password)))
        
        # Shuffle the password to avoid predictable patterns
        password = ''.join(random.sample(password, len(password)))
        
        return password

    def passStrengthCheck(self, password):
        # Define password strength criteria
        length_criteria = len(password) >= 12
        upper_criteria = bool(re.search(r'[A-Z]', password))  # Check for uppercase letters
        lower_criteria = bool(re.search(r'[a-z]', password))  # Check for lowercase letters
        digit_criteria = bool(re.search(r'\d', password))     # Check for digits
        special_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))  # Special characters
        
        # Show password strength
        if all([length_criteria, upper_criteria, lower_criteria, digit_criteria, special_criteria]):
            return "Strong"
        elif length_criteria and (upper_criteria or lower_criteria) and (digit_criteria or special_criteria):
            return "Moderate"
        else:
            return "Weak"

    def signup(self, username, email, password):
        if username in self.accs:
            return "Username already exists"
    
        # Encrypt master password
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        iv, encrypted_password, tag = self.encrypt_password(password, key)
    
        # Save user data
        self.accs[username] = {
            "username": username,
            "email": email,
            "salt": urlsafe_b64encode(salt).decode(),
            "password": urlsafe_b64encode(encrypted_password).decode(),
            "iv": urlsafe_b64encode(iv).decode(),
            "tag": urlsafe_b64encode(tag).decode(),
            "accounts": []  # Empty list to hold accounts
        }
        self.save_data("database2.json", self.accs)
        return f"Signup successful! Welcome, {username}."
        
    def decrypt_password(self, key, iv, tag, encrypted_password):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        try:
            decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
            return decrypted_password.decode()
        except Exception:
            return None
        
    def findMasterCredentials(self, userName, password):
        # Verifies user credentials during login
        user_data = self.accs.get(userName)
        if not user_data:
            return False
            
        try:
            # Retrieve salt and decrypt stored password for verification
            salt = urlsafe_b64decode(user_data["salt"])
            iv = urlsafe_b64decode(user_data["iv"])
            encrypted_password = urlsafe_b64decode(user_data["password"])
            tag = urlsafe_b64decode(user_data["tag"])
            key = self.derive_key(password, salt)
            decrypted_Password = self.decrypt_password(key, iv, tag, encrypted_password)
            
            # If decryption failed, return False
            if decrypted_Password is None:
                return False
                
            # Check if the decrypted password matches the input password
            return decrypted_Password == password
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def addAcc(self, userName, password, accountId, accountPassword):
        # Master password sent for encryption
        salt = urlsafe_b64decode(self.accs[userName]["salt"])
        key = self.derive_key(password, salt)
        
        accData = self.accs[userName]
        accs = accData['accounts']
        
        # Check if account ID already exists
        if accountId in [acc["id"] for acc in accs]:
            return "Account with that ID already exists."
            
        # Using the master password for encryption
        iv, encryptedPassword, tag = self.encrypt_password(accountPassword, key)
        
        accs.append({
            "id": accountId,
            "password": urlsafe_b64encode(encryptedPassword).decode(),
            "iv": urlsafe_b64encode(iv).decode(),
            "tag": urlsafe_b64encode(tag).decode()
        })
        self.save_data('database2.json', self.accs)
        return "Account added successfully!"
    
    def removeAcc(self, userName, index):
        user_data = self.accs.get(userName)
        if not user_data:
            return "User not found"
            
        accs = user_data['accounts']
        
        if index < 0 or index >= len(accs):
            return "Invalid account index"
            
        accId = accs[index]['id']
        del accs[index]
        self.save_data('database2.json', self.accs)
        return f"Account with id: {accId} removed"
            
    def modifyPass(self, userName, password, index, newPass):
        # Encryption using the master password
        salt = urlsafe_b64decode(self.accs[userName]['salt'])
        key = self.derive_key(password, salt)
        
        if index < 0 or index >= len(self.accs[userName]['accounts']):
            return "Invalid account index"
    
        accData = self.accs[userName]
        accs = accData['accounts']
        
        # Encrypting the new password
        iv, encrpytedPassword, tag = self.encrypt_password(newPass, key)
        accs[index]['password'] = urlsafe_b64encode(encrpytedPassword).decode()
        accs[index]['iv'] = urlsafe_b64encode(iv).decode()
        accs[index]['tag'] = urlsafe_b64encode(tag).decode()
        self.save_data('database2.json', self.accs)
        return "Password changed successfully!"
        
    def retrievePass(self, userName, password, index):
        # Decryption using the master password
        salt = urlsafe_b64decode(self.accs[userName]['salt'])
        key = self.derive_key(password, salt)
        
        if index < 0 or index >= len(self.accs[userName]['accounts']):
            return None
            
        account = self.accs[userName]['accounts'][index]
        iv = urlsafe_b64decode(account['iv'])
        tag = urlsafe_b64decode(account['tag'])
        encrypted_password = urlsafe_b64decode(account['password'])
        
        decryptedPassword = self.decrypt_password(key, iv, tag, encrypted_password)
        pyperclip.copy(decryptedPassword)
        return decryptedPassword

    def getAccounts(self, username):
        accounts = []
        if username in self.accs:
            for index, acc in enumerate(self.accs[username]["accounts"]):
                accounts.append({
                    "index": index,
                    "id": acc['id']
                })
        return accounts
            
    def resetMasterPassword(self, username, new_password):
        # Encrypt the new password
        salt = os.urandom(16)
        key = self.derive_key(new_password, salt)
        iv, encrypted_password, tag = self.encrypt_password(new_password, key)
    
        # Update the user's account data with the new password
        self.accs[username]["salt"] = urlsafe_b64encode(salt).decode()
        self.accs[username]["password"] = urlsafe_b64encode(encrypted_password).decode()
        self.accs[username]["iv"] = urlsafe_b64encode(iv).decode()
        self.accs[username]["tag"] = urlsafe_b64encode(tag).decode()
        self.save_data("database2.json", self.accs)
    
        return "Master password reset successfully! Please remember your new password."
        
    def getUserEmail(self, username):
        user_data = self.accs.get(username)
        if user_data and 'email' in user_data:
            return user_data['email']
        return None 