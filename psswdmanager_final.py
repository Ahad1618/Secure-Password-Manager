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

#width of all print statements
width=50

class psswdManager:
    def __init__(self):
            with open("database2.json", "r") as file:
                self.accs = json.loads(file.read())
    def load_data(self, filename):
        try:
            with open(filename, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def save_data(self, filename, data):
        with open(filename, "w") as file:
            file.write(json.dumps(data, indent=4))
            self.accs=data 

    def send_email(self,subject, body, to_email):
        # Email configuration
        from_email = "ahadahadansari8@gmail.com"  #email address of the sender
        password = "kgui evna uudx vcnr"     
        
        # Set up the MIME
        message = MIMEMultipart()
        message['From'] = from_email
        message['To'] = to_email
        message['Subject'] = subject
        
        # Add the email body to the message
        message.attach(MIMEText(body, 'plain'))
        
        try:
            # Set up the server
            server = smtplib.SMTP("smtp.gmail.com", 587)  # Gmail SMTP server and port
            server.starttls()                             # Enable security (TLS)
            server.login(from_email, password)            # Log in to the email account
            
            # Send the email
            server.sendmail(from_email, to_email, message.as_string())
            print("Email sent successfully!")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            server.quit()  # Close the server connection

    def forgetMasterpswd(self):
        found=False
        username=input("enter the username:")
        for user,inkeys in self.accs.items():
            if username in inkeys['username']:
                email=input("enter the email linked to the account:")
                if email in inkeys['email']:
                   found=True
        if(found):
            while(1):
                otp_validity=50
                sent_time=time.time()
                rPass=random.randint(100,1000)
                self.send_email("Your OTP for Secure Password Manager Access",f"""
Hello,

We have generated an OTP for your account in the Password Manager. Please use this OTP to access your account and update it as soon as possible.

***** OTP CODE:  {rPass} *****This OTP will expire in 50 seconds******

For security reasons, please do not share this OTP with anyone, and make sure to change it to something more secure after logging in.

If you did not request this temporary password, please contact our support team immediately.

Best regards,
The Password Manager Team
"""
,email
)
                choice=1
                print("OTP sent check your email (OTP WILL EXPIRE AFTER 50 seconds):")
                Pass=int(input("enter OTP:"))
                elapsed_time=time.time()-sent_time
                if(elapsed_time>otp_validity):
                    choice=int(input("OTP EXPIRED, press 1 to send again 2 to go back to the login screen:"))
                elif Pass==rPass:
                   print("change your password asap!")
                   #here we will call the reset masterpassword function before giving the control to the login function
                   self.loggedin(username,Pass)   
                else:
                    choice=int(input("incorrect OTP CODE,press 1 to send again 2 to go back to the login screen:"))    
                if choice==2:
                    break
                if choice==1:
                    continue
                else:
                    print("invalid choice! redirecting back to foreget password page:")
                    self.forgetMasterpswd()    
        else:
            print("wrong email or username entered:")
            print("redirecting to the the login page...")
        self.login()    
        
    def derive_key(self, password, salt):
        #Derives an AES key from the password and salt.
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_password(self,password,key):
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
        
        # Debugging output
        print(f"Length: {length_criteria}, Upper: {upper_criteria}, Lower: {lower_criteria}, "
              f"Digit: {digit_criteria}, Special: {special_criteria}")
        
        # show password strength
        if all([length_criteria, upper_criteria, lower_criteria, digit_criteria, special_criteria]):
            return "Strong"
        elif length_criteria and (upper_criteria or lower_criteria) and (digit_criteria or special_criteria):
            return "Moderate"
        else:
            return "Weak"

    def signup(self):
        print("Welcome to the Signup Process")
        username = input("Enter your username: ").strip()
    
       
        if username in self.accs:
            print("Username already exists. Please choose a different one.")
            return
    
        
        email = input("Enter your email address for recovery: ").strip()
    
        # Password setup
        while True:
            print("\nWould you like a suggested password? (y/n)")
            suggest = input().lower()
            if suggest == 'y':
                sPassword = self.passSuggest()
                print(f"Suggested Password: {sPassword}")
            
            password = input("Enter your password: ").strip()
    
            # Check password strength
            strength = self.passStrengthCheck(password)
            print(f"Password Strength: {strength}")
            if strength == "Weak":
                print("Your password is too weak. Please try again.")
            else:
                break
    
        confirm_password = input("Confirm your password: ").strip()
        if password != confirm_password:
            print("Passwords do not match. Signup failed.")
            return
    
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
        print(f"Signup successful! Welcome, {username}. You can now log in.")
            
    def decrypt_password(self,key,iv,tag,encrypted_password):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        try:
            decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
            return decrypted_password.decode()
        except Exception:
            return None
        
    def findMasterCredentials(self, userName, password):
        #Verifies user credentials during login
        user_data = self.accs.get(userName)
        if not user_data:
            return False
        # Retrieve salt and decrypt stored password for verification
        salt = urlsafe_b64decode(user_data["salt"])
        iv = urlsafe_b64decode(user_data["iv"])
        encrypted_password = urlsafe_b64decode(user_data["password"])
        tag = urlsafe_b64decode(user_data["tag"])
        key=self.derive_key(password,salt)
        decrypted_Password=self.decrypt_password(key,iv,tag,encrypted_password)
        return decrypted_Password==password
    
    def addAcc(self, userName, password):
        # Master password sent for encryption
        salt = urlsafe_b64decode(self.accs[userName]["salt"])
        key = self.derive_key(password, salt)
        id = input("Enter the ID to add: ").strip()
        
        suggest = input("Do you want a password suggestion? (yes/no): ").strip().lower()
        if suggest == "yes":
            suggested_password = self.passSuggest()
            print(f"Suggested Password: {suggested_password}")
        while True:
            passwd = input("Enter the password: ").strip()
            # Check password strength
            strength = self.passStrengthCheck(passwd)
            if strength == "Strong":
                break
            else:
                print(f"Your password is not strong enough. its {strength}. Please try again.")
        accData = self.accs[userName]
        accs = accData['accounts']
        # Using the sub-password for encryption
        iv, encryptedPassword, tag = self.encrypt_password(passwd, key)
        if id not in [acc["id"] for acc in accs]:  # Ensure unique ID
            accs.append({
                "id": id,
                "password": urlsafe_b64encode(encryptedPassword).decode(),
                "iv": urlsafe_b64encode(iv).decode(),
                "tag": urlsafe_b64encode(tag).decode()
            })
            self.save_data('database2.json', self.accs)
            print("Account added successfully!")
        else:
            print("Account with that ID already exists.")
        
    
    def removeAcc(self,idArr,userName):
        choice=int(input("enter the id number to remove the account(0 for 0th)"))
        if choice>=len(idArr):
            print("invalid choice!")
            return
        accId=idArr[choice]
        user_data=self.accs.get(userName)
        accs=user_data['accounts']
        for i in range(len(accs)):
            if accs[i]['id']==accId:
                del accs[i]
                print(f"account with id:{accId} removed")
                self.save_data('database2.json',self.accs)
                return
            
    def modifyPass(self,idArr,userName,password):
        #encryption using the masterpassword
        salt=urlsafe_b64decode(self.accs[userName]['salt'])
        key=self.derive_key(password,salt)
        
        choice=int(input("enter the id number to modify the password:"))
        if choice>=len(idArr):
            print("invalid choice!")
            return
        suggest = input("Do you want a password suggestion? (yes/no): ").strip().lower()
        if suggest == "yes":
           suggested_pass=self.passSuggest()    
        while True:
           newPass=input("enter the password to set:")
           strength=self.passStrengthCheck(newPass)
           if strength=='Strong':
                break
           else:
                print(f"Your password is not strong enough. its {strength}. Please try again.")
    
        accData=self.accs[userName]
        accs=accData['accounts']
        #encrypting the masterpassword
        
        iv,encrpytedPassword,tag=self.encrypt_password(newPass,key)
        accs[choice]['password']=urlsafe_b64encode(encrpytedPassword).decode()
        accs[choice]['iv']=urlsafe_b64encode(iv).decode()
        accs[choice]['tag']=urlsafe_b64encode(tag).decode()
        self.save_data('database2.json',self.accs)
        print("password changed successfully!")

    
        
    def retrievePass(self,passArr,userName,password):
        #passing all the accounts to retrieve the selected one
        #decryption using the masterpassword
        salt=urlsafe_b64decode(self.accs[userName]['salt'])
        key=self.derive_key(password,salt)
        
        choice=int(input("enter the id number to retrieve the password (0 for 0th):"))
        if choice>=len(passArr):
            print("invalid choice!")
            return
        iv=urlsafe_b64decode(self.accs[userName]['accounts'][choice]['iv'])
        tag=urlsafe_b64decode(self.accs[userName]['accounts'][choice]['tag'])
        decryptedPassword=self.decrypt_password(key,iv,tag,urlsafe_b64decode(passArr[choice]))
        pyperclip.copy(decryptedPassword)
        print("password copied to clipboard!")
        return

    def showAccs(self,username):
        passArr=[]
        idArr=[]
        for user,data in self.accs.items():
           if user == username:
               for index,acc in enumerate(data["accounts"]):
                   password_length = len(acc['password'])
                   passArr.append(acc['password'])
                   idArr.append(acc['id'])
                   masked_password = '*' * 10
                   print(f"{index}:id={acc['id']}, pass={masked_password}")
        return passArr,idArr
            
    def resetMasterPassword(self, username, old_password):
        
        print("\nYou are about to reset your master password.")
        
        while True:
            print("\nWould you like a suggested password? (y/n)")
            suggest = input().lower()
            if suggest == 'y':
                suggested_password = self.passSuggest()
                print(f"Suggested Password: {suggested_password}")
            
            new_password = input("Enter your new master password: ").strip()
    
            # Check password strength
            strength = self.passStrengthCheck(new_password)
            print(f"Password Strength: {strength}")
            if strength == "Weak":
                print("Your new password is too weak. Please try again.")
            else:
                break
    
        confirm_password = input("Confirm your new master password: ").strip()
        if new_password != confirm_password:
            print("Passwords do not match. Password reset failed.")
            return
    
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
    
        print("Master password reset successfully! Please remember your new password.")        
            
    def loggedin(self,username,password):
        while(1):
            print("welcome! "+username)
            print("Registered Accs:")
            passArr,idArr=self.showAccs(username)
            choice=int(input("press 1 to retrieve a password \n press 2 to modify a password \n press 3 to add an account\n press 4 to remove an account\n press 5 to reset masterpassword\n press -1 to exit"))
            if choice==1:
               self.retrievePass(passArr,username,password)
            elif choice==2:
                #password suggestor and strength checker will be called inside this
                self.modifyPass(idArr,username,password)
            elif choice==3:
                #password suggestor and strength checker will be called inside this
                self.addAcc(username,password)
            elif choice==4:
                self.removeAcc(idArr,username)
            elif choice == 5: 
                self.resetMasterPassword(username, password)
            elif choice==-1:
                passArr.clear()
                idArr.clear()
                self.mainmenu()
            else:
                print("wrong choice! enter again:")
        
    def login(self):
        print("-" * 50 + " Login Page " + "-" * 50)
        while True:
            choice1 = int(input("Press 1 to continue login and press 2 to go back to main menu: "))
            if choice1 == 2:
                break
            elif(choice1==1):
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                if self.findMasterCredentials(username, password):
                    print("Login successful!")
                    self.loggedin(username,password)
                else:
                    print("Wrong credentials!")
                    choice2 = int(input("Press 1 if forgot password, 2 to go back to main menu, or 3 to try again: "))
                    if choice2 == 1:
                        self.forgetMasterpswd()
                    elif choice2 == 2:
                        self.mainmenu()
                    else:
                        continue        
            else:
                print("wrong choice! enter again:")

    def mainmenu(self):
        while True:
            print("-" * 50 + " Welcome to Password Manager " + "-" * 50)
            prompt1="Enter 1 to login, 2 for signup, 3 for exit: "
            choice1 = int(input(prompt1.rjust(90)))
            if choice1 == 1:
                self.login()
            elif choice1 == 2:
                self.signup()
            elif choice1==3:
                sys.exit()
            else:
                print("wrong choice entered enter again!")
e1=psswdManager()
e1.mainmenu()