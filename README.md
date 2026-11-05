# E2EE-Demo-Chat

Demoprogramm für die Ende-zu-Ende-Verschlüsselung in Messengern. Es zeigt die Schritte des Signal-Protokolls (Schlüsselerzeugung, X3DH, Double Ratchet, AES-GCM) sichtbar auf der Konsole.

Voraussetzungen: Python 3.10 oder neuer, dann `pip install -r requirements.txt`.

Start in drei Konsolenfenstern:

    python server.py            (Server; mit --mitm als Angreifer in der Mitte)
    python client.py Alice
    python client.py Bob

Befehle im Client: `/send <Name> <Text>`, `/verify <Name>`, `/keys`, `/details`, `/quit`.
