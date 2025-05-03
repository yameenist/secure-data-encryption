import streamlit as st
import hashlib
import json
import os
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# ---------- CONFIGURATION ----------
DATA_FILE = "data.json"
KEY_FILE = "secret.key"
LOCKOUT_TIME = 60  # in seconds
PBKDF2_ITERATIONS = 100_000

# ---------- KEY MANAGEMENT ----------
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return f.read()

KEY = load_or_create_key()
cipher = Fernet(KEY)

# ---------- DATA MANAGEMENT ----------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {"users": {}}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

db = load_data()

# ---------- PASSWORD HASHING ----------
def hash_password(password, salt=None):
    salt = salt or os.urandom(16).hex()
    dk = pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return {"hash": dk.hex(), "salt": salt}

def verify_password(password, hashed_data):
    new_hash = hash_password(password, hashed_data["salt"])["hash"]
    return new_hash == hashed_data["hash"]

# ---------- SESSION STATE INIT ----------
if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_until" not in st.session_state:
    st.session_state.lockout_until = 0

# ---------- AUTHENTICATION ----------
def login(username, password):
    user = db["users"].get(username)
    if not user:
        return False
    if verify_password(password, user["auth"]):
        st.session_state.user = username
        st.session_state.failed_attempts = 0
        return True
    return False

def register(username, password):
    if username in db["users"]:
        return False
    db["users"][username] = {
        "auth": hash_password(password),
        "records": []
    }
    save_data(db)
    return True

# ---------- ENCRYPTION/DECRYPTION ----------
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ---------- UI ----------
st.title("🔐 Multi-User Secure Data Vault")

menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Menu", menu)

# ---------- TIME-BASED LOCKOUT ----------
now = time.time()
if st.session_state.lockout_until > now:
    st.error(f"🔒 Locked out. Try again in {int(st.session_state.lockout_until - now)}s.")
    st.stop()

# ---------- HOME ----------
if choice == "Home":
    st.subheader("Welcome")
    st.write("Securely store and retrieve encrypted data. Each user has private access.")

# ---------- LOGIN ----------
elif choice == "Login":
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if login(username, password):
            st.success("✅ Logged in!")
        else:
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_until = time.time() + LOCKOUT_TIME
                st.error("🔒 Too many failed attempts. You're locked out.")
            else:
                st.error("❌ Invalid credentials")

# ---------- REGISTER ----------
elif choice == "Register":
    st.subheader("🆕 Register New Account")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if register(username, password):
            st.success("✅ Registered successfully! You can now log in.")
        else:
            st.error("❌ Username already exists.")

# ---------- STORE DATA ----------
elif choice == "Store Data":
    if not st.session_state.user:
        st.warning("Please login to store data.")
    else:
        st.subheader("📦 Store Data")
        data = st.text_area("Enter your data:")
        if st.button("Encrypt and Save"):
            if data:
                encrypted = encrypt_data(data)
                db["users"][st.session_state.user]["records"].append(encrypted)
                save_data(db)
                st.success("✅ Data stored securely!")
                st.text_area("Encrypted Data:", encrypted, height=100)
            else:
                st.error("⚠️ Please enter some data.")

# ---------- RETRIEVE DATA ----------
elif choice == "Retrieve Data":
    if not st.session_state.user:
        st.warning("Please login to retrieve data.")
    else:
        st.subheader("🔍 Your Stored Data")
        records = db["users"][st.session_state.user]["records"]
        if records:
            selected = st.selectbox("Select an entry to decrypt", records)
            if st.button("Decrypt"):
                decrypted = decrypt_data(selected)
                st.success("✅ Decrypted Data:")
                st.text_area("Result", decrypted, height=100)
        else:
            st.info("No stored records found.")

