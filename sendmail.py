from smtplib import SMTP
import sys

# Récupérer l'adresse de l'expéditeur et le mot de passe des variables d'environnement
#absender = os.environ.get("EMAIL_SENDER")
#passwd = os.environ.get("EMAIL_PASSWORD")

absender = "jguimfackjeuna@studenten.hs-bremerhaven.de"
passwd ="Jeunaj3"

zieladresse = "jguimfackjeuna@smail.hs-bremerhaven.de"

if zieladresse is None or absender is None:
    sys.exit("Gib deine Eigene Adresse als Ziel- und Absenderadresse an.")

header = f"""From: {absender}
To: {zieladresse}
Subject: Test
Date: 2023-12-11
"""

body = """Hallo Lars,

schön mit dir zu reden.

Grüße
  Lars
"""

email = "\n".join([header, body])
host = 'smail.hs-bremerhaven.de'
port = 587
uid = "jguimfackjeuna"

if uid is None or passwd is None:
    sys.exit("Gib die Nutzer-ID deines Mailproviders und das Passwort im Code an.")

print("start")

with SMTP(host, port) as smtp:
    smtp.ehlo("thunder")
    print(".")
    smtp.starttls()
    print("..")
    smtp.login(uid, passwd)
    print("...")
    smtp.sendmail(absender, zieladresse, email.encode())
    print("Schau in deine Mailbox")
