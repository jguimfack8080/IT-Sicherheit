from flask import Flask, request, jsonify, send_file
import gnupg
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from werkzeug.utils import secure_filename
import os
import hashlib
import uuid
import json
import re

app = Flask(__name__)
gpg = gnupg.GPG()

# Directory for storing temporary PGP keys
upload_folder = 'upload_folder'
allowed_extensions = {'asc'}

# Email server settings
smtp_server = 'smtp.gmail.com'
smtp_port = 587
smtp_username = 'coronaapp65@gmail.com'
smtp_password = 'ywdjntzxyllwoclk'

app.config['UPLOAD_FOLDER'] = upload_folder

# File where account information will be stored
accounts_file = 'accounts.json'

def load_accounts():
    """ Load accounts from a JSON file """
    if os.path.exists(accounts_file):
        with open(accounts_file, 'r') as file:
            return json.load(file)
    return {}

def save_accounts(accounts):
    """ Save accounts to a JSON file """
    with open(accounts_file, 'w') as file:
        # Utilisez l'indentation pour formater le fichier JSON
        json.dump(accounts, file, indent=4)

# Load accounts at the start
account_passwords = load_accounts()

def send_email(subject, body, to_email, attachment=None):
    # SMTP connection setup
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)

    # Create email message
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = smtp_username
    msg['To'] = to_email

    # Add body
    body_text = MIMEText(body)
    msg.attach(body_text)

    # Add attachment if present
    if attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{attachment.filename}"')
        msg.attach(part)

    # Send email
    server.sendmail(smtp_username, [to_email], msg.as_string())
    server.quit()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def send_challenge_email(email, challenge):
    subject = "[ACME-PGP] RESPONSE"
    body = f"Guten Tag,\n\nTo complete your PGP key registration, please respond to the following challenge:\n\n{challenge}\n\nPlease reply to this email with the above challenge to confirm your identity.\n\nBest regards,\nYour PGP Support Team"
    send_email(subject, body, email)

def generate_account_id(suggested_account_id):
    """ Generate a modified account ID based on the suggested account ID or generate a random UUID """
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, suggested_account_id)) if suggested_account_id else str(uuid.uuid4())

def hash_password(password):
    """ Generate a secure hash of the password """
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/create_account', methods=['POST'])
def create_account():
    data = request.json  # Utilize request.json to obtain data in JSON format
    suggested_account_id = data.get('account-id')
    password = data.get('password')
    
    if not suggested_account_id or not password:
        return jsonify({'error': 'Konto-ID und Passwort sind erforderlich'}), 400
    # Check if the account already exists
    if suggested_account_id in account_passwords:
        return jsonify({"error": "Account already exists with the provided account-id."}), 400   
    # Otherwise, create the account
    account_id = suggested_account_id if suggested_account_id else generate_account_id()
    

    account_passwords[account_id] = {'password_hash': hash_password(password)}
    modified_account_id = generate_account_id(suggested_account_id)  # Generate modified account ID

    # Include the modified account ID in the response
    response_data = {"account-id": account_id, "modified-account-id": modified_account_id}
    
    # Add the modified account ID to the account_passwords dictionary
    account_passwords[account_id]["modified-account-id"] = modified_account_id

    # Save the updated accounts
    save_accounts(account_passwords)

    return jsonify(response_data)


@app.route('/register_pgp_key', methods=['POST'])
def register_pgp_key():
    # Reload the accounts data in case it has been updated
    account_passwords = load_accounts()

    data = request.form
    account_id = data.get('account-id')
    password = data.get('password')
    email_address = data.get('email-adresse')  # The new email address
    key_id = data.get('key-id')  # The identifier of the public key

    # Check authentication
    if (account_id not in account_passwords or 
        'password_hash' not in account_passwords[account_id] or 
        account_passwords[account_id]['password_hash'] != hash_password(password)):
        return jsonify({"error": "Authentication failed."})

    # Check if a valid email address is provided
    if not is_valid_email(email_address):
        return jsonify({"error": "Invalid email address."})

    # Check if a PGP key is present
    file = request.files.get('pgp-key')
    if not file or not allowed_file(file.filename):
        return jsonify({"error": "Invalid or missing PGP key."})

    # Store the PGP key
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    filename = secure_filename(f"{account_id}_temp_key.asc")
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)


    # Generate a challenge and send it via email
    challenge = os.urandom(40).hex()

    # Store the challenge in the account's dictionary
    if account_id not in account_passwords:
        account_passwords[account_id] = {'password_hash': hash_password(password)}

    account_passwords[account_id]['challenge'] = challenge

    # Save the updated accounts with the challenge
    save_accounts(account_passwords)

    # Send the challenge via email
    send_challenge_email(email_address, challenge)

    return jsonify({"message": "Challenge sent to email."})

def is_valid_email(email):
    # Simple email validation function (can be expanded)
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

@app.route('/respond_to_challenge', methods=['POST'])
def respond_to_challenge():
    # Reload the accounts data in case it has been updated
    account_passwords = load_accounts()
    data = request.get_json()
    account_id = data.get('account-id')
    password = data.get('password')
    response = data.get('response')

    # Check authentication
    if (account_id not in account_passwords or 
        'password_hash' not in account_passwords[account_id] or 
        account_passwords[account_id]['password_hash'] != hash_password(password)):
        return jsonify({"error": "Authentication failed."})

    # Check the challenge-response
    if ('challenge' in account_passwords[account_id] and 
        account_passwords[account_id]['challenge'] == response):
        # Load the temporary PGP key
        filename = secure_filename(f"{account_id}_temp_key.asc")
        signed_pgp_key_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Sign the PGP key
        with open(signed_pgp_key_path, 'rb') as file:
            signed_pgp_key = gpg.sign(file.read(), passphrase='Maman2000')

        # Remove the challenge value
        # Supprimer complètement la clé 'challenge' si elle existe
        account_passwords[account_id].pop('challenge', None)

        save_accounts(account_passwords)  # Update the accounts.json file

        # Return the signed PGP key as an attachment
        response_data = {
            "message": "Challenge successful.",
            "signed_pgp_key": signed_pgp_key.data.decode('utf-8')
        }
        
        return jsonify(response_data), 200, {'Content-Disposition': f'attachment; filename="{account_id}_signed_pgp_key.asc"'}
    return jsonify({"error": "Invalid response to challenge."})


if __name__ == '__main__':
    app.run(debug=True)
