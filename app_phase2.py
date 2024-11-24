from flask import Flask, render_template, request
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import re

app_phase2 = Flask(__name__)

# AES Secret Key (32 bytes for AES-256)
AES_KEY = b"this_is_a_strong_32_byte_key123!"  # Replace with a secure key
IV = b"1234567890123456"  # Initialization vector (must be 16 bytes)

# Database connection function
def connect_db():
    """
    Connect to the SQLite database file 'nookala.db'.
    This function ensures that the database is properly initialized.
    """
    db_path = os.path.join(os.getcwd(), "nookala.db")
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found at {db_path}. Ensure 'nookala.db' exists in the project folder.")
    return sqlite3.connect(db_path, isolation_level=None)


# AES Encryption
def encrypt_password(password):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()

    # Add padding to the password (block size = 128 bits)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()

    # Encrypt and return base64-encoded ciphertext
    return base64.b64encode(encryptor.update(padded_data) + encryptor.finalize()).decode()


# AES Decryption
def decrypt_password(encrypted_password):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(IV), backend=backend)
    decryptor = cipher.decryptor()

    # Ensure Base64 string is properly padded
    missing_padding = len(encrypted_password) % 4
    if missing_padding:
        encrypted_password += "=" * (4 - missing_padding)

    # Decode from base64 and decrypt
    decrypted_data = decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(decrypted_data) + unpadder.finalize()).decode()


# Input Validation Function
def validate_input(value):
    """
    Validate input to allow only alphanumeric characters and underscores.
    """
    return re.match(r"^[a-zA-Z0-9_]+$", value)


@app_phase2.route("/")
def home():
    return (
        """
        <div style="
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: skyblue;
            font-family: Arial, sans-serif;
            text-align: center;
        ">
            <h1>Welcome to the User System</h1>
            <p>
                <a href="/login" style="
                    color: #007bff;
                    text-decoration: none;
                    font-size: 18px;
                ">
                    Go to Login
                </a>
            </p>
            <p>
                <a href="/register" style="
                    color: #007bff;
                    text-decoration: none;
                    font-size: 18px;
                ">
                    Go to Registration
                </a>
            </p>
        </div>
        """
    )

# Registration Page
@app_phase2.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Validate input
        if not validate_input(username) or not validate_input(password):
            return "Invalid input detected! Only alphanumeric characters are allowed."

        # Encrypt the password
        encrypted_password = encrypt_password(password)

        # Save the username and encrypted password to the database
        conn = connect_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, encrypted_password),
            )
            conn.commit()
            conn.close()
            return (
                """
                <div style="
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background-color: skyblue;
                    font-family: Arial, sans-serif;
                    text-align: center;
                ">
                    <h1>Registration Successful!</h1>
                    <p>
                        <a href="/login" style="
                            color: #007bff;
                            text-decoration: none;
                            font-size: 18px;
                        ">
                            Click here to login
                        </a>
                    </p>
                </div>
                """
            )
        except sqlite3.IntegrityError:
            return "Username already exists!"
    return render_template("register.html")


# Login Page
@app_phase2.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Validate input
        if not validate_input(username) or not validate_input(password):
            return "Invalid input detected! Only alphanumeric characters are allowed."

        # Encrypt the input password
        encrypted_input_password = encrypt_password(password)

        conn = connect_db()
        cursor = conn.cursor()

        # Secure SQL query using parameterized queries
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        print(f"Generated Query: {query} with parameters: {username}, {encrypted_input_password}")  # Debugging

        try:
            cursor.execute(query, (username, encrypted_input_password))
            result = cursor.fetchone()
            conn.close()

            if result:
                # Display the login success message with user data
                return (
                    f"""
                    <div style="
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        background-color: skyblue;
                        font-family: Arial, sans-serif;
                        text-align: center;
                    ">
                        <h1>Login Successful!</h1>
                        <p>User Data: {result}</p>
                        <p>
                            <a href="/" style="
                                color: #007bff;
                                text-decoration: none;
                                font-size: 18px;
                            ">
                                Go to Home
                            </a>
                        </p>
                    </div>
                    """
                )
            else:
                return "Invalid credentials!"
        except sqlite3.OperationalError as e:
            conn.close()
            return f"SQL Error: {e}"
    return render_template("login.html")


if __name__ == "__main__":
    app_phase2.run(debug=True)