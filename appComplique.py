from flask import Flask, request, jsonify
import gnupg
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import os
import hashlib
import uuid
import json
import subprocess


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

accounts_file = 'accounts.json'

def load_accounts():
    """ Load accounts from a JSON file """
    if os.path.exists(accounts_file) and os.path.getsize(accounts_file) > 0:
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
    try:
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
            filename = getattr(attachment, 'filename', 'attachment.asc')
            part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
            msg.attach(part)

        # Send email
        server.sendmail(smtp_username, [to_email], msg.as_string())
    finally:
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

@app.before_request
def load_accounts_before_request():
    global account_passwords
    account_passwords = load_accounts()

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


@app.route('/register_key', methods=['POST'])
def register_key():
    account_id = request.form.get('account-id')
    password = request.form.get('password')
    email = request.form.get('email')
    key_id = request.form.get('key-id')

    if not account_id or not password or not email or not key_id:
        return jsonify({'error': 'Tous les champs sont obligatoires'}), 400

    # Vérifier l'authentification de l'utilisateur
    if account_id not in account_passwords or hash_password(password) != account_passwords[account_id]['password_hash']:
        return jsonify({'error': 'Authentification échouée'}), 401

    # Vérifier si l'utilisateur a déjà enregistré une clé
    if 'public_key' in account_passwords[account_id]:
        return jsonify({'error': 'Vous avez déjà enregistré une clé'}), 400

    # Vérifier si le fichier de clé est attaché
    if 'key_file' not in request.files or not allowed_file(request.files['key_file'].filename):
        return jsonify({'error': 'Veuillez joindre un fichier de clé valide au format .asc'}), 400

    # Sauvegarder la clé publique
    key_file = request.files['key_file']
    key_content = key_file.read().decode('utf-8')  # Convertir bytes en str
    account_passwords[account_id]['public_key'] = key_content
    

    # Envoyer le challenge token par email
    challenge_token = str(uuid.uuid4())
    # Ajouter le challenge_token, email, key-id au dictionnaire account_passwords
    account_passwords[account_id]['challenge_token'] = challenge_token
    account_passwords[account_id]['email'] = email
    account_passwords[account_id]['key-id'] = key_id
    save_accounts(account_passwords)

    send_challenge_email(email, challenge_token)

    return jsonify({'message': 'Challenge token envoyé par email'})

def sign_and_send_key(account_id):
    gpg.encoding = 'utf-8'

    try:
        # Récupérer le key_id à partir du fichier JSON
        key_id = account_passwords[account_id]['key-id']

        # Importieren der öffentlichen Schlüssel
        public_key = account_passwords[account_id]['public_key']
        imported_key = gpg.import_keys(public_key)
        if not imported_key.fingerprints:
            raise ValueError("Schlüssel konnte nicht importiert werden")

        # Signieren der Schlüssel mit der key_id
        signed_key = gpg.sign(public_key, keyid=key_id, detach=True, clearsign=True)
        if not signed_key:
            raise ValueError("Schlüssel konnte nicht signiert werden")

        # Schreiben der signierten Schlüssel in eine Datei
        signed_key_filename = f"signed_key_{key_id}.asc"
        with open(signed_key_filename, 'w', encoding='utf-8') as signed_key_file:
            signed_key_file.write(signed_key.data)

        # Senden der signierten Schlüssel mit gpg
        subprocess.run(['gpg', '--send-keys', key_id])

        return signed_key_filename
    except Exception as e:
        print(f"Fehler beim Signieren und Senden des Schlüssels: {e}")
        return None



# Nouvelle route pour la réponse au challenge
@app.route('/respond_to_challenge', methods=['POST'])
def respond_to_challenge():
    data = request.json
    account_id = data.get('account-id')
    password = data.get('password')
    challenge_token = data.get('challenge-token')

    if not account_id or not password or not challenge_token:
        return jsonify({'error': 'Tous les champs sont obligatoires'}), 400

    # Vérifier l'authentification de l'utilisateur
    if account_id not in account_passwords or hash_password(password) != account_passwords[account_id]['password_hash']:
        return jsonify({'error': 'Authentification échouée'}), 401

    # Vérifier si l'utilisateur a un challenge token en attente
    if 'challenge_token' not in account_passwords[account_id]:
        return jsonify({'error': 'Aucun challenge token en attente'}), 400

    # Vérifier si le challenge token correspond
    if account_passwords[account_id]['challenge_token'] != challenge_token:
        return jsonify({'error': 'Challenge token incorrect'}), 401

    # Signer la clé
    signed_key = sign_and_send_key(account_passwords[account_id]['key-id'])

    # Envoyer la clé signée par email
    send_email(
        subject="[ACME-PGP] Votre clé PGP signée",
        body="Votre clé PGP a été signée avec succès.",
        to_email=account_passwords[account_id]['email'],
        attachment=signed_key,
    )

    # Effacer le challenge token et la clé stockée
    del account_passwords[account_id]['challenge_token']
    del account_passwords[account_id]['public_key']
    save_accounts(account_passwords)

    return jsonify({'message': 'Clé signée envoyée par email'})


if __name__ == '__main__':
    app.run(debug=True)
