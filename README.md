# 🔐 Simple Python Password Manager

This is a beginner-friendly Password Manager built with Python. It allows users to securely store their credentials, generate strong passwords, check password strength, and recover access using OTP-based email verification.

## ✨ Features

- 🔑 Master Account Sign-Up and Login
- 📧 Forgot Master Password (OTP via Email)
- 🔐 AES-GCM Encryption for Passwords
- 🧂 Secure Key Derivation using PBKDF2 + Salt
- 🧠 Password Strength Checker (Weak, Moderate, Strong)
- ⚙️ Password Generator
- 📋 Clipboard Integration for Easy Copying (using `pyperclip`)
- 📁 Local JSON File as a Simple Database

## 📦 Requirements

Install the required packages using pip:

```bash
pip install cryptography pyperclip
