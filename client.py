# Client des Demo-Chats für einen Teilnehmer.
# Aufruf: python client.py <Name> [--server http://127.0.0.1:5000]
import argparse
import sys
import threading
import time

import requests

from protocol import (Ratchet, b64, detail, fingerprint, line, make_bundle, new_key_pair, public_bytes, section,
                      short, toggle_details, unb64, x3dh_initiator, x3dh_responder)

POLL_INTERVAL = 1  # Sekunden zwischen zwei Abfragen des Postfachs
OPK_COUNT = 5      # Anzahl der Einmal-Prekeys beim Start
HELP = "Befehle: /send <Name> <Text>   /verify <Name>   /keys   /details   /quit"

# Zustand des Clients; server, me und die Schlüssel werden beim Start gesetzt (main und create_keys).
server = ""
me = ""
identity_key = None    # Identitätsschlüssel IK (privat)
signed_prekey = None   # signierter Prekey SPK (privat)
one_time_prekeys = {}  # Nummer -> Einmal-Prekey (privat)
sessions = {}          # Name des Partners -> Ratchet
peer_identity = {}     # Name des Partners -> sein öffentlicher Identitätsschlüssel (für die Sicherheitsnummer)

# Eingabeschleife und Hintergrund-Thread arbeiten beide mit den Sitzungen und Schlüsseln. Die Sperre (Lock) sorgt dafür,
# dass immer nur einer von beiden gleichzeitig daran arbeitet; sonst könnten Senden und Empfangen denselben Ratchet
# zur selben Zeit verändern. "with lock:" wartet, bis die Sperre frei ist, und gibt sie am Ende des Blocks wieder frei.
lock = threading.Lock()


def create_keys():
    # Erzeugt alle eigenen Schlüsselpaare: Identitätsschlüssel, signierten Prekey und die Einmal-Prekeys 1 bis OPK_COUNT.
    global identity_key, signed_prekey
    identity_key = new_key_pair()
    signed_prekey = new_key_pair()
    for opk_id in range(1, OPK_COUNT + 1):
        one_time_prekeys[opk_id] = new_key_pair()


def print_keys():
    # Zeigt die öffentlichen Teile der eigenen Schlüssel und die Nummern der noch vorhandenen Einmal-Prekeys,
    # bei ausführlicher Ausgabe auch jeden Einmal-Prekey einzeln.
    tag = me[0].upper()
    section(f"Schlüssel von {me}")
    line(f"Identitätsschlüssel IK_{tag}", short(public_bytes(identity_key)))
    line(f"signierter Prekey SPK_{tag}", short(public_bytes(signed_prekey)) + "  (hier ohne Signatur)")
    detail("  Hinweis: im echten Protokoll mit dem Identitätsschlüssel signiert")
    numbers = " ".join(f"#{opk_id}" for opk_id in one_time_prekeys)
    if numbers == "":
        numbers = "keine mehr"
    line("Einmal-Prekeys", numbers)
    for opk_id, opk in one_time_prekeys.items():
        detail(f"  Einmal-Prekey #{opk_id}", short(public_bytes(opk)))
    print("Die privaten Schlüssel bleiben auf diesem Gerät.")


def register():
    # Meldet den Teilnehmer beim Server an (POST /register) und hinterlegt dort das Bündel mit den öffentlichen Schlüsseln.
    # json=... wandelt das Dict in JSON um und sendet es als Körper mit.
    # raise_for_status() bricht mit einer Fehlermeldung ab, wenn der Server mit einem Fehlercode (4xx oder 5xx) antwortet.
    bundle = make_bundle(identity_key, signed_prekey, one_time_prekeys)
    answer = requests.post(server + "/register", json={"name": me, "bundle": bundle})
    answer.raise_for_status()


def start_session(peer):
    # Baut als Initiator eine Sitzung mit peer auf: Bündel vom Server holen, X3DH rechnen, Double Ratchet starten.
    # Rückgabe: die Startdaten ("initial") für die erste Nachricht, oder None, wenn der Server kein Bündel herausgibt.
    answer = requests.get(server + "/bundle/" + peer, params={"for": me})
    if answer.status_code == 404:
        print(f"Unbekannter Empfänger: {peer}")
        return None
    if answer.status_code == 409:
        print(f"{peer} hat keine Einmal-Prekeys mehr auf dem Server.")
        return None
    answer.raise_for_status()
    bundle = answer.json()["bundle"]

    sk, ek_pub, opk_id = x3dh_initiator(identity_key, bundle, me, peer)
    ratchet = Ratchet()
    ratchet.init_alice(sk, unb64(bundle["spk"]))
    sessions[peer] = ratchet
    peer_identity[peer] = unb64(bundle["ik"])
    # Damit kann der Partner X3DH von seiner Seite nachrechnen:
    return {"ik": b64(public_bytes(identity_key)), "ek": b64(ek_pub), "opk_id": opk_id}


def start_responder_session(sender, initial):
    # Baut als Empfänger einer ersten Nachricht die Sitzung mit sender auf: X3DH aus den Startdaten nachrechnen,
    # Double Ratchet starten. Eine bestehende Sitzung mit sender wird dabei ersetzt.
    sk = x3dh_responder(identity_key, signed_prekey, one_time_prekeys, initial, me, sender)
    ratchet = Ratchet()
    ratchet.init_bob(sk, signed_prekey)
    sessions[sender] = ratchet
    peer_identity[sender] = unb64(initial["ik"])


def send_message(peer, text):
    # Verschlüsselt eine Nachricht und schickt sie über den Server an peer (POST /send).
    # Gibt es noch keine Sitzung, wird sie zuerst aufgebaut, und die Startdaten werden mit der ersten Nachricht mitgeschickt.
    with lock:
        initial = None
        if peer not in sessions:
            initial = start_session(peer)
            if initial is None:
                return
        section(f"Double Ratchet: Nachricht an {peer}")
        header, nonce, ciphertext = sessions[peer].encrypt(text)
        envelope = {"initial": initial, "header": header, "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        answer = requests.post(server + "/send", json={"from": me, "to": peer, "envelope": envelope})
        answer.raise_for_status()


def receive(message):
    # Verarbeitet eine Nachricht aus dem Postfach: bei Startdaten zuerst die Sitzung aufbauen, dann entschlüsseln und ausgeben.
    sender = message["from"]
    envelope = message["envelope"]
    with lock:
        try:
            if envelope["initial"] is not None:
                start_responder_session(sender, envelope["initial"])
            if sender not in sessions:
                print(f"Nachricht von {sender} ohne Sitzung verworfen.")
                return
            section(f"Double Ratchet: Nachricht von {sender}")
            text = sessions[sender].decrypt(envelope["header"], unb64(envelope["nonce"]), unb64(envelope["ciphertext"]))
        except ValueError as error:
            print(f"Nachricht von {sender} verworfen:")
            print(f"  {error}")
            return
    print(f"{sender}: {text}")


def verify(peer):
    # Zeigt die Sicherheitsnummer aus dem eigenen Identitätsschlüssel und dem des Partners.
    # Stimmen die Nummern auf beiden Geräten überein, gehören die Schlüssel wirklich zu den beiden Teilnehmern.
    with lock:
        if peer not in peer_identity:
            print(f"Noch keine Sitzung mit {peer}.")
            return
        number = fingerprint(public_bytes(identity_key), peer_identity[peer])
    print(f"Sicherheitsnummer mit {peer} (auf beiden Geräten vergleichen)")
    print(number)


def poll_inbox():
    # Läuft dauerhaft im Hintergrund-Thread: holt jede Sekunde das Postfach ab (GET /inbox/<me>) und verarbeitet die
    # Nachrichten in der Reihenfolge des Eingangs. Das regelmäßige Abfragen ist nötig, weil HTTP nach dem Prinzip
    # Frage/Antwort arbeitet: Der Server kann einem Client nichts von sich aus schicken.
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            answer = requests.get(server + "/inbox/" + me)
        except requests.ConnectionError:
            continue  # Server nicht erreichbar: im nächsten Durchlauf erneut versuchen
        if answer.status_code != 200:
            continue
        messages = answer.json()["messages"]
        for message in messages:
            receive(message)
        if len(messages) > 0:
            # Die Ausgabe hat die Eingabezeile unterbrochen, deshalb wird die Eingabeaufforderung neu ausgegeben.
            print("> ", end="", flush=True)


def main():
    global server, me
    sys.stdout.reconfigure(encoding="utf-8")  # Umlaute unter Windows

    # Befehlszeile auswerten: Name ist Pflicht, --server ist optional
    parser = argparse.ArgumentParser(description="E2EE-Demo-Client")
    parser.add_argument("name")
    parser.add_argument("--server", default="http://127.0.0.1:5000")
    args = parser.parse_args()
    me = args.name
    server = args.server

    create_keys()
    print_keys()
    try:
        register()
    except requests.ConnectionError:
        print(f"Server {server} nicht erreichbar. Läuft server.py?")
        return
    line("Bündel beim Server hinterlegt:", server)

    # Hintergrund-Thread für das Postfach starten; er läuft parallel zur Eingabeschleife
    # daemon=True: Der Thread endet automatisch, sobald das Hauptprogramm endet
    poller = threading.Thread(target=poll_inbox, daemon=True)
    poller.start()

    # Eingabeschleife: liest Befehle, bis "/quit" eingegeben wird
    print(HELP)
    while True:
        command = input("> ").strip()
        if command == "/quit":
            break
        elif command.startswith("/send "):
            # split(" ", 2) teilt höchstens zweimal, der Text darf also Leerzeichen enthalten:
            # "/send Bob Hallo du" -> ["/send", "Bob", "Hallo du"]
            parts = command.split(" ", 2)
            if len(parts) < 3:
                print("Aufruf: /send <Name> <Text>")
                continue
            send_message(parts[1], parts[2])
        elif command.startswith("/verify "):
            verify(command.split(" ", 1)[1].strip())
        elif command == "/keys":
            with lock:
                print_keys()
        elif command == "/details":
            if toggle_details():
                print("Ausführliche Ausgabe: an (alle Zwischenwerte)")
            else:
                print("Ausführliche Ausgabe: aus")
        elif command != "":
            print("Unbekannter Befehl. " + HELP)


if __name__ == "__main__":
    main()
