# Server des Demo-Chats: hinterlegt die Bündel der Teilnehmer und leitet Nachrichten über Postfächer weiter.
# Seine Ausgabe zeigt, was ein Messenger-Server von jeder Nachricht zu sehen bekommt.
# Mit --mitm wird der Server zum Angreifer in der Mitte (Man-in-the-Middle): Er gibt statt der echten Bündel sein eigenes aus,
# vereinbart mit jeder Seite getrennt Schlüssel, liest alle Nachrichten mit und verschlüsselt sie für den Empfänger neu.
import argparse
import logging
import sys
import time

from flask import Flask, request

from protocol import (Ratchet, b64, line, make_bundle, new_key_pair, public_bytes, section, short, unb64, x3dh_initiator, x3dh_responder)

app = Flask(__name__)

# Gesamter Zustand des Servers, nur im Arbeitsspeicher (geht beim Beenden verloren):
bundles = {}  # Name -> Bündel des Teilnehmers (nur öffentliche Schlüssel)
inbox = {}    # Name -> Liste der Nachrichten, die auf Abholung warten

# Zustand im MITM-Modus:
MITM_NAME = "MITM"   # Name in den eigenen Ausgaben, ergibt die Kürzel IK_M, SPK_M usw.
MITM_OPK_COUNT = 10  # Anzahl eigener Einmal-Prekeys
mitm = False         # wird beim Start mit --mitm eingeschaltet
mitm_ik = None       # eigener Identitätsschlüssel des Servers (privat)
mitm_spk = None      # eigener signierter Prekey des Servers (privat)
mitm_opks = {}       # Nummer -> eigener Einmal-Prekey (privat)
mitm_unused = []     # Nummern der eigenen Einmal-Prekeys, die noch nicht herausgegeben wurden
# (Absender, Empfänger) als key -> Dict mit den beiden Ratchet-Objekten der Kommunikationspartner (Name als Key, Ratchet als Value).
# Jedes Paar steht in beiden Reihenfolgen darin (also erst A->B, dann B->A), damit Nachrichten in beide Richtungen dasselbe Paar-Dict finden.
mitm_sessions = {}

# Jede Funktion mit "@app.post(...)" oder "@app.get(...)" bearbeitet die HTTP-Anfragen an den angegebenen Pfad.
# request.get_json() liest den JSON-Körper der Anfrage; ein zurückgegebenes Dict wandelt Flask automatisch in eine JSON-Antwort um.
# "return {...}, 404" sendet zusätzlich den Statuscode 404 ("nicht gefunden").


@app.post("/register")
def register():
    # Anmeldung eines Teilnehmers: speichert sein Bündel unter seinem Namen.
    data = request.get_json()
    name = data["name"]
    bundle = data["bundle"]
    bundles[name] = bundle
    # Ein Postfach wird nur angelegt, wenn noch keines existiert, damit nach einem Neustart des Clients wartende Nachrichten erhalten bleiben.
    if name not in inbox:
        inbox[name] = []
    ik = short(unb64(bundle["ik"]))
    spk = short(unb64(bundle["spk"]))
    print(f"Bündel von {name} hinterlegt ({len(bundle['opks'])} Einmal-Prekeys)")
    print(f"  IK {ik}   SPK {spk}")
    return {"ok": True}


def take_bundle(name, requester):
    # Gibt das gespeicherte Bündel von name mit genau einem Einmal-Prekey zurück, oder None, wenn keiner mehr übrig ist.
    # Der herausgegebene Einmal-Prekey wird aus dem Vorrat gelöscht, damit ihn niemand ein zweites Mal bekommt.
    stored = bundles[name]
    if len(stored["opks"]) == 0:
        return None
    opk = stored["opks"].pop(0)
    print(f"{requester} holt Bündel von {name}: Einmal-Prekey #{opk['id']} herausgegeben")
    print(f"  und vom Server gelöscht (noch {len(stored['opks'])} übrig)")
    return {"ik": stored["ik"], "spk": stored["spk"], "opks": [opk]}


@app.get("/bundle/<name>")
def get_bundle(name):
    # Gibt das Bündel des Teilnehmers <name> heraus; Flask übergibt den Pfadteil <name> als Parameter.
    # Im MITM-Modus bekommt der Anfragende stattdessen das eigene Bündel des Servers unter dem Namen <name>.
    if name not in bundles:
        return {"error": f"unbekannter Name: {name}"}, 404
    # Der Anfragende steht hinter "?for=", z. B. /bundle/Bob?for=Alice
    requester = request.args.get("for", "?")
    if mitm:
        if len(mitm_unused) == 0:
            return {"error": f"{name} hat keine Einmal-Prekeys mehr"}, 409 # eigentlich hat der Server selbst keine mehr, aber wir tun so, als wäre es der echte Teilnehmer
        opk_id = mitm_unused.pop(0)
        own = make_bundle(mitm_ik, mitm_spk, {opk_id: mitm_opks[opk_id]})
        print(f"MITM: gebe {requester} mein eigenes Bündel als das von {name} aus")
        return {"name": name, "bundle": own}
    bundle = take_bundle(name, requester)
    if bundle is None:
        # 409 ("Konflikt"): Der Vorrat an Einmal-Prekeys ist aufgebraucht.
        return {"error": f"{name} hat keine Einmal-Prekeys mehr"}, 409
    return {"name": name, "bundle": bundle}


def print_server_view(sender, receiver, envelope):
    # Sicht des Servers: Metadaten (Zeit, von, an, Größe), Header und Chiffrat.
    # Den Nachrichtenschlüssel kennt er nicht, den Klartext kann er also nicht lesen.
    clock = time.strftime("%H:%M:%S")
    header = envelope["header"]
    ciphertext = unb64(envelope["ciphertext"])
    dh_short = short(unb64(header["dh"]))
    print(f"{clock}  {sender} -> {receiver}   Chiffrat {len(ciphertext)} Byte   (kein Klartext)")
    print(f"          Header dh={dh_short} n={header['n']}   Chiffrat {short(ciphertext)}")
    if envelope["initial"] is not None:
        opk_id = envelope["initial"]["opk_id"]
        print(f"          erste Nachricht mit X3DH-Startdaten (IK, EK, OPK #{opk_id})")


@app.post("/send")
def send():
    # Nimmt eine Nachricht {"from", "to", "envelope"} an, gibt die Sicht des Servers aus und legt sie ins Postfach des Empfängers.
    # Im MITM-Modus wird die Nachricht vorher entschlüsselt, mitgelesen und für den Empfänger neu verschlüsselt.
    data = request.get_json()
    sender = data["from"]
    receiver = data["to"]
    envelope = data["envelope"]
    if receiver not in inbox:
        return {"error": f"unbekannter Name: {receiver}"}, 404
    print_server_view(sender, receiver, envelope)
    if mitm:
        envelope = mitm_relay(sender, receiver, envelope)
        if envelope is None:
            return {"ok": True}
    inbox[receiver].append({"from": sender, "envelope": envelope})
    return {"ok": True}


@app.get("/inbox/<name>")
def get_inbox(name):
    # Gibt alle wartenden Nachrichten von <name> zurück und leert das Postfach, sodass jede Nachricht genau einmal abgeholt wird.
    if name not in inbox:
        return {"error": f"unbekannter Name: {name}"}, 404
    messages = inbox[name]
    inbox[name] = []
    return {"messages": messages}


# --- MITM-Modus ------------------------------------------------------------

def create_mitm_keys():
    # Erzeugt die eigenen Schlüssel des Servers, mit denen er sich gegenüber jedem Teilnehmer als dessen Partner ausgibt.
    global mitm_ik, mitm_spk
    mitm_ik = new_key_pair()
    mitm_spk = new_key_pair()
    for opk_id in range(1, MITM_OPK_COUNT + 1):
        mitm_opks[opk_id] = new_key_pair()
        mitm_unused.append(opk_id)
    section("MITM-MODUS: Server tauscht Schlüssel aus")
    line("Identitätsschlüssel IK_M", short(public_bytes(mitm_ik)))
    line("signierter Prekey SPK_M", short(public_bytes(mitm_spk)))


def mitm_start(initiator, target, initial):
    # Baut bei der ersten Nachricht eines Paars zwei getrennte Sitzungen auf:
    # 1. mit dem Initiator, der glaubt, mit target zu sprechen (X3DH als Empfänger mit den eigenen Schlüsseln),
    # 2. mit target, dem gegenüber sich der Server als Initiator ausgibt (X3DH als Initiator mit dem echten Bündel von target).
    # Rückgabe: Startdaten für die erste Nachricht an target. Ist kein Einmal-Prekey von target mehr übrig, folgt ein ValueError.
    print(f"MITM: neue Sitzung {initiator} -> {target}, zwei getrennte Schlüsselvereinbarungen")
    sk_1 = x3dh_responder(mitm_ik, mitm_spk, mitm_opks, initial, MITM_NAME, initiator)
    with_initiator = Ratchet()
    with_initiator.init_bob(sk_1, mitm_spk)

    real_bundle = take_bundle(target, MITM_NAME)
    if real_bundle is None:
        raise ValueError(f"{target} hat keine Einmal-Prekeys mehr")
    sk_2, ek_pub, opk_id = x3dh_initiator(mitm_ik, real_bundle, MITM_NAME, target)
    with_target = Ratchet()
    with_target.init_alice(sk_2, unb64(real_bundle["spk"]))

    pair = {initiator: with_initiator, target: with_target}
    mitm_sessions[(initiator, target)] = pair
    mitm_sessions[(target, initiator)] = pair
    return {"ik": b64(public_bytes(mitm_ik)), "ek": b64(ek_pub), "opk_id": opk_id}


def mitm_relay(sender, receiver, envelope):
    # Entschlüsselt die Nachricht mit der Sitzung zum Absender, gibt den Klartext aus und verschlüsselt ihn mit der Sitzung zum Empfänger neu.
    # Rückgabe: neuer Umschlag für den Empfänger, oder None, wenn die Nachricht verworfen wird.
    initial = None
    try:
        if envelope["initial"] is not None:
            initial = mitm_start(sender, receiver, envelope["initial"])
        if (sender, receiver) not in mitm_sessions:
            print("MITM: keine Sitzung für dieses Paar, unverändert weitergeleitet")
            return envelope
        pair = mitm_sessions[(sender, receiver)]

        section(f"MITM: Nachricht von {sender} entschlüsseln")
        text = pair[sender].decrypt(envelope["header"], unb64(envelope["nonce"]), unb64(envelope["ciphertext"]))
        print(f"MITM liest: {text}")
        section(f"MITM: für {receiver} neu verschlüsseln")
        header, nonce, ciphertext = pair[receiver].encrypt(text)
    except ValueError as error:
        print(f"MITM: Nachricht verworfen ({error})")
        return None
    return {"initial": initial, "header": header, "nonce": b64(nonce), "ciphertext": b64(ciphertext)}


def main():
    global mitm
    # Konsolenausgabe auf UTF-8, damit Umlaute unter Windows stimmen.
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="E2EE-Demo-Server")
    parser.add_argument("--mitm", action="store_true", help="Server als Angreifer in der Mitte starten")
    mitm = parser.parse_args().mitm
    # Flasks Webserver "werkzeug" meldet sonst jede Anfrage, also auch die sekündlichen Postfach-Abfragen; so erscheinen nur echte Fehler.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    section("Server läuft auf http://127.0.0.1:5000")
    if mitm:
        create_mitm_keys()
    # 127.0.0.1: nur vom eigenen Rechner aus erreichbar.
    # threaded=False: Anfragen werden nacheinander bearbeitet, nie gleichzeitig, sodass sich zwei Anfragen beim Ändern
    # von bundles, inbox und den MITM-Sitzungen nicht in die Quere kommen können.
    app.run(host="127.0.0.1", port=5000, threaded=False)


if __name__ == "__main__":
    main()
