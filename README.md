#  SecureVault – Local Password Manager with 2FA

SecureVault is a simple desktop password manager built with Python and Tkinter.  
It stores passwords securely in an encrypted local vault and includes TOTP 2FA protection for unlocking.  

---

##  Features

-  Local password vault — stores all entries in an encrypted JSON file  
-  Master password  
-  Two-Factor Authentication (2FA) using Google Authenticator/Twilio Authy (QR-based)  
-  Audit logging — records every lock/unlock event  
-  Clean Tkinter GUI built for easy use  
-  Auto-clear fields after locking for privacy  

---

##  How It Works

1. On first run, you’ll be asked to create a master password.  
2. The app generates a QR code for Google Authenticator/Twilio Authy — scan it to enable 2FA.  
3. You can then add, view, and manage your passwords inside the vault.  
4. The vault encrypts all data locally (no cloud involved).  
5. Every unlock and action is logged in `audit_log.txt`.

---

##  Tech Stack

- Python 3.11+
- Tkinter (GUI)
- cryptography (AES encryption)
- pyotp (2FA generation and validation)
- qrcode (QR code display)
- pillow (for QR rendering)

---

##  Installation

Clone the repo:
```bash
git clone https://github.com/Balasudhan123/Password-Manager-With-TOTP.git
cd SecureVault
