# secure-data-encryption

1. Passkeys hashed (e.g., SHA-256).   
2. Secure Encryption & Decryption.
3.  Encrypt data using Caesar cipher or Fernet (from cryptography library).
4.  Decrypt only when the correct passkey is provided.
5. Authentication & Security
Allow three attempts before forcing a reauthorization/login page.
Display failed attempts count.

. Streamlit UI (User-Friendly Interface)
Home Page: Options to store new data or retrieve data.
Insert Data Page:

User enters text + passkey, and it’s stored securely.
Retrieve Data Page:
User provides a passkey to decrypt data.
If failed 3 times, redirect to the Login Page for reauthorization.
Login Page: Simple login mechanism before retrying.

Data Persistence

Store encrypted data in a JSON file instead of memory.
Load data on app startup.
Advanced Security Features

Time-based lockout for failed attempts.
Use PBKDF2 hashing instead of SHA-256 for extra security.
Multi-User System

Allow multiple users to store and retrieve their own data.
Use a user authentication system with Streamlit.
