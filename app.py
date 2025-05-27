import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (static for session)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Initialize session state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"encrypted_text": {"encrypted_text": str, "passkey": hashed_str}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Utility: Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Utility: Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Utility: Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    record = st.session_state.stored_data.get(encrypted_text)

    if record and record["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# Navigation
st.sidebar.title("🔐 Navigation")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Choose a page", menu)

# Home Page
if choice == "Home":
    st.title("🏠 Secure Data Encryption System")
    st.markdown("""
        Use this app to securely **store** and **retrieve** text using encrypted passkeys.
        - Data is stored **in-memory**.
        - Incorrect passkeys after 3 attempts will require login.
    """)

# Store Data Page
elif choice == "Store Data":
    st.title("📂 Store Data")
    user_data = st.text_area("Enter your data to encrypt:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 You must reauthorize to continue.")
        st.switch_page("Login")

    st.title("🔍 Retrieve Data")
    encrypted_input = st.text_area("Enter the encrypted data:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            decrypted = decrypt_data(encrypted_input, passkey_input)

            if decrypted:
                st.success("✅ Decryption successful!")
                st.code(decrypted, language="text")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔐 Too many failed attempts! Redirecting to Login.")
                    st.session_state.authorized = False
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

# Login Page
elif choice == "Login":
    st.title("🔑 Reauthorize Access")
    login_input = st.text_input("Enter master password to continue:", type="password")

    if st.button("Login"):
        if login_input == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")
