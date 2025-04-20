# Secure Password Manager

A secure password manager application with GUI built with Python and Tkinter.

## Features

- **User Authentication**: Secure login with encrypted credentials
- **Password Management**: Add, retrieve, modify, and remove account passwords
- **Password Strength Checker**: Built-in password strength evaluation
- **Password Generator**: Automatic generation of strong passwords
- **Account Recovery**: Email-based OTP recovery system
- **Secure Encryption**: AES encryption with cryptography library

## Getting Started

### Prerequisites

- Python 3.6+
- Required packages:
  - tkinter
  - cryptography
  - pyperclip

### Installation

1. Clone the repository or download the files
2. Install the required packages:
   ```
   pip install cryptography pyperclip
   ```
3. Run the application:
   ```
   python main.py
   ```

## Usage

1. **First Time Use**:
   - Click "Sign Up" to create a new account
   - Enter your username, email, and a strong master password
   - Use the suggested password feature if needed

2. **Login**:
   - Enter your username and master password to access your accounts

3. **Managing Passwords**:
   - Add new accounts with the "Add Account" button
   - Copy passwords to clipboard directly
   - Modify or remove existing accounts
   - Reset your master password as needed

4. **Forgot Password**:
   - Use the "Forgot Password" feature to receive an OTP via email
   - Reset your master password with the OTP

## Security Features

- AES-GCM encryption for all stored passwords
- PBKDF2 key derivation function for password security
- Email-based two-factor authentication for account recovery
- Password strength evaluation and suggestions

## Project Structure

- `main.py`: Entry point for the application
- `core.py`: Core functionality and encryption methods
- `gui.py`: Tkinter-based graphical user interface
- `database2.json`: Encrypted storage for all accounts and passwords

## License

This project is for educational purposes only. Use at your own risk.

## Acknowledgments

- Built with Python and Tkinter
- Uses the cryptography library for secure encryption 