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
    subject = "[ACME-PGP] Challenge"
    body = f"Guten Tag,\n\nUm Ihre PGP-Schlüsselregistrierung abzuschließen, antworten Sie bitte auf die folgende Herausforderung:\n\n{challenge}\n\nBitte antworten Sie auf diese E-Mail mit der oben genannten Herausforderung, um Ihre Identität zu bestätigen.\n\nMit freundlichen Grüßen,\nIhr PGP-Support-Team"
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
    # Überprüfen, ob das Konto bereits existiert
    if suggested_account_id in account_passwords:
        return jsonify({"error": "Konto existiert bereits mit der bereitgestellten Kontonummer."}), 400   
    # Andernfalls Konto erstellen
    account_id = suggested_account_id if suggested_account_id else generate_account_id()
    
    # Hinzufügen des Kontos zum account_passwords-Dictionary
    account_passwords[account_id] = {'password_hash': hash_password(password)}
    modified_account_id = generate_account_id(suggested_account_id)  # Geänderte Kontonummer generieren

    # Geänderte Kontonummer in der Antwort einschließen
    response_data = {"account-id": account_id, "modified-account-id": modified_account_id}
    
    # Geänderte Kontonummer zum account_passwords-Dictionary hinzufügen
    account_passwords[account_id]["modified-account-id"] = modified_account_id

    # Aktualisierte Konten speichern
    save_accounts(account_passwords)

    return jsonify(response_data)



@app.route('/register_key', methods=['POST'])
def register_key():
    account_id = request.form.get('account-id')
    password = request.form.get('password')
    email = request.form.get('email')
    key_id = request.form.get('key-id')

    if not account_id or not password or not email or not key_id:
        return jsonify({'error': 'Alle Felder sind erforderlich'}), 400

    # Überprüfen der Authentifizierung des Benutzers
    if account_id not in account_passwords or hash_password(password) != account_passwords[account_id]['password_hash']:
        return jsonify({'error': 'Authentifizierung fehlgeschlagen'}), 401

    # Überprüfen, ob der Benutzer bereits einen Schlüssel registriert hat
    if 'public_key' in account_passwords[account_id]:
        return jsonify({'error': 'Sie haben bereits einen Schlüssel registriert'}), 400

    # Überprüfen, ob die Schlüsseldatei angehängt ist
    if 'key_file' not in request.files or not allowed_file(request.files['key_file'].filename):
        return jsonify({'error': 'Bitte fügen Sie eine gültige Schlüsseldatei im Format .asc hinzu'}), 400

    # Speichern des öffentlichen Schlüssels
    key_file = request.files['key_file']
    key_content = key_file.read().decode('utf-8')  # Bytes in String umwandeln
    account_passwords[account_id]['public_key'] = key_content

    # Challenge-Token per E-Mail senden
    challenge_token = str(uuid.uuid4())

    send_challenge_email(email, challenge_token)
    # Challenge-Token, E-Mail, Key-ID zum account_passwords-Dictionary hinzufügen
    account_passwords[account_id]['challenge_token'] = challenge_token
    account_passwords[account_id]['email'] = email
    account_passwords[account_id]['key-id'] = key_id
    save_accounts(account_passwords)

    return jsonify({'message': 'Challenge-Token per E-Mail gesendet'})


def sign_key(public_key):
    gpg.encoding = 'utf-8'

    try:
        # Importieren der öffentlichen Schlüssel
        imported_key = gpg.import_keys(public_key)
        if not imported_key.fingerprints:
            print("Schlüssel konnte nicht importiert werden")

        # Signieren der Schlüssel
        signed_key = gpg.sign(public_key, detach=True, clearsign=True)
        if not signed_key:
            print("Schlüssel konnte nicht signiert werden")

        return signed_key
    except Exception as e:
        print(f"Fehler beim Signieren des Schlüssels: {e}")
        return None



# Nouvelle route pour la réponse au challenge
@app.route('/respond_to_challenge', methods=['POST'])
def respond_to_challenge():
    data = request.json
    account_id = data.get('account-id')
    password = data.get('password')
    challenge_token = data.get('challenge-token')

    if not account_id or not password or not challenge_token:
        return jsonify({'error': 'Alle Felder sind erforderlich'}), 400

    # Überprüfen der Authentifizierung des Benutzers
    if account_id not in account_passwords or hash_password(password) != account_passwords[account_id]['password_hash']:
        return jsonify({'error': 'Authentifizierung fehlgeschlagen'}), 401

    # Überprüfen, ob der Benutzer ein ausstehendes Challenge-Token hat
    if 'challenge_token' not in account_passwords[account_id]:
        return jsonify({'error': 'Kein ausstehendes Challenge-Token vorhanden'}), 400

    # Überprüfen, ob das Challenge-Token übereinstimmt
    if account_passwords[account_id]['challenge_token'] != challenge_token:
        return jsonify({'error': 'Challenge-Token inkorrekt'}), 401

    # Schlüssel signieren
    signed_key = sign_key(account_passwords[account_id]['public_key'])

    # Signierten Schlüssel per E-Mail senden
    send_email(
        subject="[ACME-PGP] Ihr signierter PGP-Schlüssel",
        body="Ihr PGP-Schlüssel wurde erfolgreich signiert.",
        to_email=account_passwords[account_id]['email'],
        attachment=signed_key,
    )

    # Challenge-Token und gespeicherten Schlüssel löschen
    del account_passwords[account_id]['challenge_token']
    del account_passwords[account_id]['public_key']
    save_accounts(account_passwords)

    return jsonify({'message': 'Signierter Schlüssel per E-Mail gesendet'})

if __name__ == '__main__':
    app.run(debug=True)
