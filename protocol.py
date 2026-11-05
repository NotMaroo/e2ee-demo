# Gemeinsame Bausteine für Server und Client: Ausgabe, Base64, Schlüssel, X3DH, Double Ratchet und Sicherheitsnummer.
#
# Alle Schlüsselpaare sind X25519-Paare. Ein eigenes Paar wird als privates Schlüsselobjekt gespeichert;
# der öffentliche Teil lässt sich jederzeit daraus berechnen (public_bytes).
# Öffentliche Schlüssel anderer Teilnehmer liegen als 32 Bytes vor.
import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# --- Ausgabe -----------------------------------------------------------

# Ausführliche Ausgabe: zeigt zusätzlich alle Zwischenwerte (DH-Werte, Kettenschlüssel, Header, Nonce usw.).
# Der Client schaltet sie mit /details um.
details = False


def short(b: bytes) -> str:
    # Gibt Bytes gekürzt als Hex-Text zurück: die ersten 4 Byte (8 Hex-Zeichen) und "…", z. B. "3f9a1c0b…".
    # Das reicht, um zwei Werte auf dem Bildschirm zu vergleichen; gerechnet wird immer mit allen Bytes.
    return b[:4].hex() + "…"


def line(label: str, value: str):
    # Gibt "Bezeichnung   Wert" aus. ":<34" füllt die Bezeichnung auf 34 Zeichen auf, damit alle Werte untereinander stehen.
    print(f"{label:<34}{value}")


def detail(label: str, value: str = ""):
    # Wie line(), aber nur bei eingeschalteter ausführlicher Ausgabe. Ohne value wird nur label ausgegeben.
    if not details:
        return
    if value == "":
        print(label)
    else:
        line(label, value)


def toggle_details() -> bool:
    # Schaltet die ausführliche Ausgabe um und gibt den neuen Zustand zurück.
    # "global" ist nötig, damit die Zuweisung die Variable auf Modulebene ändert, statt eine lokale anzulegen.
    global details
    details = not details # Invertiert den booleschen Wert: True -> False, False -> True
    return details


def section(title: str):
    # Gibt eine Leerzeile und eine Abschnittsüberschrift aus, z. B. "== Schlüssel von Alice ==".
    print()
    print(f"== {title} ==")


# --- Base64 und Schlüssel ----------------------------------------------

def b64(data: bytes) -> str:
    # Bytes -> Base64-Text. JSON kann keine Bytes enthalten, deshalb werden Schlüssel, Nonces und Chiffrate als Text übertragen.
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    # Base64-Text -> Bytes (Umkehrung von b64).
    return base64.b64decode(text)


def new_key_pair() -> X25519PrivateKey:
    # Erzeugt ein neues, zufälliges X25519-Schlüsselpaar.
    return X25519PrivateKey.generate()


def public_bytes(key: X25519PrivateKey) -> bytes:
    # Öffentlicher Teil eines eigenen Schlüsselpaars als 32 Bytes.
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def dh(private_key: X25519PrivateKey, public_key: bytes) -> bytes:
    # Diffie-Hellman auf X25519: Der eigene private und der fremde öffentliche Schlüssel ergeben 32 Bytes.
    # Die Gegenseite erhält mit ihrem privaten und unserem öffentlichen Schlüssel dieselben Bytes.
    peer_key = X25519PublicKey.from_public_bytes(public_key)
    return private_key.exchange(peer_key)


def make_bundle(ik, spk, opks: dict) -> dict:
    # Bündel = öffentliche Teile von Identitätsschlüssel, signiertem Prekey und allen Einmal-Prekeys, so wie der Server es speichert.
    # opks ordnet jeder Nummer einen Einmal-Prekey zu.
    opk_list = []
    for opk_id, opk in opks.items():
        opk_list.append({"id": opk_id, "key": b64(public_bytes(opk))})
    return {"ik": b64(public_bytes(ik)), "spk": b64(public_bytes(spk)), "opks": opk_list}


def hkdf(data: bytes, length: int, salt, info: bytes) -> bytes:
    # HKDF mit SHA-256: leitet aus data einen gleichmäßig zufälligen Schlüssel mit length Bytes ab.
    # salt=None bedeutet 32 Nullbytes; info trennt verschiedene Verwendungszwecke voneinander.
    kdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return kdf.derive(data)


# --- X3DH ----------------------------------------------------------------

# Vorspann vor den DH-Werten laut X3DH-Spezifikation (32 Bytes mit dem Wert 0xFF). Er dient der Bereichstrennung
# (domain separation): Im echten Protokoll signiert der Identitätsschlüssel auch (XEdDSA), und der feste Vorspann
# verhindert, dass Eingaben der Schlüsselableitung mit Daten der Signatur verwechselt werden können.
# Hier wird nicht signiert; F steht für die genaue Umsetzung der Vorgabe.
F = b"\xff" * 32


def x3dh_initiator(ik, bundle: dict, me: str, peer: str):
    # X3DH aus Sicht des Initiators, also dessen, der die erste Nachricht schickt.
    # ik = eigener Identitätsschlüssel (privat), bundle = Bündel des Partners vom Server mit genau einem Einmal-Prekey.
    # Rückgabe: Startgeheimnis SK, öffentlicher Ephemeralschlüssel und Nummer des verwendeten Einmal-Prekeys.
    a = me[0].upper()    # Kürzel für die Ausgabe, z. B. "A" für Alice
    b = peer[0].upper()
    ik_b = unb64(bundle["ik"])
    spk_b = unb64(bundle["spk"])
    opk_id = bundle["opks"][0]["id"]
    opk_b = unb64(bundle["opks"][0]["key"])

    section(f"X3DH: Schlüsselvereinbarung mit {peer}")
    print(f"Bündel von {peer} vom Server: IK_{b}, SPK_{b}, Einmal-Prekey #{opk_id}")
    detail(f"  Identitätsschlüssel IK_{b}", short(ik_b))
    detail(f"  signierter Prekey SPK_{b}", short(spk_b))
    detail(f"  Einmal-Prekey OPK_{b} #{opk_id}", short(opk_b))

    # Der Ephemeralschlüssel wird nur für diesen einen Austausch erzeugt.
    ek = new_key_pair()
    ek_pub = public_bytes(ek)
    print(f"Neuer Ephemeralschlüssel EK_{a}, nur für diesen Austausch")
    detail(f"  Ephemeralschlüssel EK_{a}", short(ek_pub))

    dh1 = dh(ik, spk_b)
    dh2 = dh(ek, ik_b)
    dh3 = dh(ek, spk_b)
    dh4 = dh(ek, opk_b)
    sk = hkdf(F + dh1 + dh2 + dh3 + dh4, 32, None, b"E2EE-Demo X3DH")
    print("DH1–DH4 berechnet, SK = HKDF(F || DH1 || DH2 || DH3 || DH4)")
    detail(f"  DH1 = DH(IK_{a}, SPK_{b})", short(dh1))
    detail(f"  DH2 = DH(EK_{a}, IK_{b})", short(dh2))
    detail(f"  DH3 = DH(EK_{a}, SPK_{b})", short(dh3))
    detail(f"  DH4 = DH(EK_{a}, OPK_{b})", short(dh4))
    line("Startgeheimnis SK", f"{short(sk)}  (muss bei {peer} gleich sein)")

    # Privater Ephemeralschlüssel und DH-Werte werden nicht mehr gebraucht und verworfen.
    # del entfernt nur die Namen; ein sicheres Überschreiben des Speichers bietet Python nicht.
    del ek, dh1, dh2, dh3, dh4
    print(f"EK_{a} (privat) und DH1–DH4 gelöscht.")
    return sk, ek_pub, opk_id


def x3dh_responder(ik, spk, opks: dict, initial: dict, me: str, peer: str) -> bytes:
    # X3DH aus Sicht des Empfängers der ersten Nachricht: rechnet dieselben vier DH-Werte von der anderen Seite und gibt SK zurück.
    # ik, spk = eigene private Schlüssel, opks = eigene Einmal-Prekeys (Nummer -> Schlüssel),
    # initial = Startdaten aus der ersten Nachricht (IK und EK des Initiators, Nummer des verwendeten Einmal-Prekeys).
    # Der verwendete Einmal-Prekey wird aus opks gelöscht.
    a = peer[0].upper()  # Initiator
    b = me[0].upper()
    ik_a = unb64(initial["ik"])
    ek_a = unb64(initial["ek"])
    opk_id = initial["opk_id"]
    if opk_id not in opks:
        raise ValueError(f"Einmal-Prekey #{opk_id} ist nicht vorhanden")
    opk = opks[opk_id]

    section(f"X3DH: Schlüsselvereinbarung mit {peer}")
    print(f"Erste Nachricht von {peer} enthält IK_{a}, EK_{a} und Einmal-Prekey #{opk_id}")
    detail(f"  Identitätsschlüssel IK_{a}", short(ik_a))
    detail(f"  Ephemeralschlüssel EK_{a}", short(ek_a))
    detail(f"  eigener Einmal-Prekey #{opk_id}", short(public_bytes(opk)))

    dh1 = dh(spk, ik_a)
    dh2 = dh(ik, ek_a)
    dh3 = dh(spk, ek_a)
    dh4 = dh(opk, ek_a)
    sk = hkdf(F + dh1 + dh2 + dh3 + dh4, 32, None, b"E2EE-Demo X3DH")
    print("DH1–DH4 von dieser Seite berechnet, SK = HKDF(F || DH1 || DH2 || DH3 || DH4)")
    detail(f"  DH1 = DH(SPK_{b}, IK_{a})", short(dh1))
    detail(f"  DH2 = DH(IK_{b}, EK_{a})", short(dh2))
    detail(f"  DH3 = DH(SPK_{b}, EK_{a})", short(dh3))
    detail(f"  DH4 = DH(OPK_{b}, EK_{a})", short(dh4))
    line("Startgeheimnis SK", f"{short(sk)}  (muss bei {peer} gleich sein)")

    # Ein Einmal-Prekey darf nur einmal verwendet werden. opks ist dasselbe Dict wie beim Aufrufer, das Löschen wirkt also auch dort.
    del opks[opk_id]
    del opk, dh1, dh2, dh3, dh4
    print(f"Einmal-Prekey #{opk_id} (privat) und DH1–DH4 gelöscht.")
    return sk


# --- Double Ratchet --------------------------------------------------------

def kdf_rk(rk: bytes, dh_out: bytes):
    # Root-KDF: Aus Root-Schlüssel (als salt) und neuem DH-Wert (als Eingabe) entstehen ein neuer Root-Schlüssel
    # und ein neuer Kettenschlüssel, je 32 Bytes.
    out = hkdf(dh_out, 64, rk, b"E2EE-Demo Ratchet")
    return out[:32], out[32:]


def kdf_ck(ck: bytes):
    # Ketten-KDF mit HMAC-SHA256: Eingabe 0x01 ergibt den Nachrichtenschlüssel, Eingabe 0x02 den nächsten Kettenschlüssel.
    # Aus dem neuen Kettenschlüssel lässt sich der alte nicht zurückrechnen.
    mk = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    ck_next = hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return ck_next, mk


def header_aad(header: dict) -> bytes:
    # Zusatzdaten (AAD) für AES-GCM: der Header als JSON mit sortierten Schlüsseln, damit beide Seiten exakt dieselben Bytes bilden.
    # Der Header wird nicht verschlüsselt, aber mitgeschützt: Wird er unterwegs verändert, schlägt die Entschlüsselung fehl.
    return json.dumps(header, sort_keys=True).encode()


class Ratchet:
    # Zustand des Double Ratchet für die Sitzung mit einem Partner.
    # Vereinfachung: Nachrichten einer Richtung kommen in der gesendeten Reihenfolge an, daher gibt es keine übersprungenen Nachrichtenschlüssel.

    def __init__(self):
        self.rk = None         # Root-Schlüssel
        self.dh_pair = None    # eigenes Ratchet-Schlüsselpaar
        self.dh_remote = None  # Ratchet-Schlüssel des Partners (öffentlich)
        self.ck_send = None    # Kettenschlüssel der Sendekette
        self.ck_recv = None    # Kettenschlüssel der Empfangskette
        self.n_send = 0        # Zähler der Nachrichten in der Sendekette
        self.n_recv = 0        # Zähler der Nachrichten in der Empfangskette

    def init_alice(self, sk: bytes, peer_spk: bytes):
        # Start beim Initiator: Der signierte Prekey des Partners dient als dessen erster Ratchet-Schlüssel.
        # Mit einem neuen eigenen Ratchet-Schlüssel folgt sofort ein DH-Ratchet-Schritt, aus dem die Sendekette entsteht.
        self.dh_pair = new_key_pair()
        self.dh_remote = peer_spk
        self.rk, self.ck_send = kdf_rk(sk, dh(self.dh_pair, peer_spk))
        print("Double Ratchet gestartet: Root-Schlüssel und Sendekette aus SK")
        detail("  eigener Ratchet-Schlüssel", short(public_bytes(self.dh_pair)))
        detail("  Root-Schlüssel", short(self.rk))
        detail("  Kettenschlüssel (Sendekette)", short(self.ck_send))

    def init_bob(self, sk: bytes, spk: X25519PrivateKey):
        # Start beim Empfänger der ersten Nachricht: Das Paar des eigenen signierten Prekeys ist das erste Ratchet-Schlüsselpaar,
        # SK der erste Root-Schlüssel. Die Ketten entstehen beim DH-Ratchet-Schritt mit der ersten empfangenen Nachricht.
        self.dh_pair = spk
        self.rk = sk

    def dh_ratchet_step(self, remote: bytes):
        # DH-Ratchet-Schritt, sobald der Partner einen neuen Ratchet-Schlüssel schickt: Mit dem bisherigen eigenen Paar entsteht
        # die neue Empfangskette, mit einem neuen eigenen Paar die neue Sendekette. Beide Male ändert sich auch der Root-Schlüssel.
        self.dh_remote = remote
        self.rk, self.ck_recv = kdf_rk(self.rk, dh(self.dh_pair, remote))
        self.dh_pair = new_key_pair()
        self.rk, self.ck_send = kdf_rk(self.rk, dh(self.dh_pair, remote))
        self.n_send = 0
        self.n_recv = 0
        print("DH-Ratchet-Schritt: neuer Root-Schlüssel, neue Empfangs- und Sendekette")
        detail("  Ratchet-Schlüssel des Partners", short(remote))
        detail("  eigener neuer Ratchet-Schlüssel", short(public_bytes(self.dh_pair)))
        detail("  Root-Schlüssel", short(self.rk))
        detail("  Kettenschlüssel (Sendekette)", short(self.ck_send))

    def encrypt(self, plaintext: str):
        # Verschlüsselt eine Nachricht. Rückgabe: Header, Nonce, Chiffrat.
        detail("  Klartext", plaintext)
        old_ck = self.ck_send
        self.ck_send, mk = kdf_ck(self.ck_send)

        # Header: eigener öffentlicher Ratchet-Schlüssel und Zähler n
        n = self.n_send
        header = {"dh": b64(public_bytes(self.dh_pair)), "n": n}
        self.n_send += 1
        # AES-256-GCM mit dem Nachrichtenschlüssel als AES-Schlüssel und 12 zufälligen Bytes als Nonce.
        # Das Chiffrat endet mit einem 16 Byte langen Prüfwert (Tag), der Text und Header schützt.
        nonce = os.urandom(12)
        ciphertext = AESGCM(mk).encrypt(nonce, plaintext.encode(), header_aad(header))

        detail("  Kettenschlüssel (Sendekette)", short(old_ck))
        detail("    nächster Kettenschlüssel", short(self.ck_send))
        line(f"Nachrichtenschlüssel (n = {n})", f"{short(mk)}  (danach gelöscht)")
        detail("  Header: dh / n", f"{short(public_bytes(self.dh_pair))} / {n}")
        detail("  Nonce", short(nonce))
        line("Chiffrat an den Server", f"{short(ciphertext)}  ({len(ciphertext)} Byte)")
        del mk
        return header, nonce, ciphertext

    def decrypt(self, header: dict, nonce: bytes, ciphertext: bytes) -> str:
        # Entschlüsselt eine Nachricht. Enthält der Header einen neuen Ratchet-Schlüssel des Partners, kommt zuerst ein DH-Ratchet-Schritt.
        # Beim ersten Empfang ist dh_remote noch None; der Vergleich ergibt dann ebenfalls "neu".
        remote = unb64(header["dh"])
        detail("  Header: dh / n", f"{short(remote)} / {header['n']}")
        if remote != self.dh_remote:
            self.dh_ratchet_step(remote)

        old_ck = self.ck_recv
        self.ck_recv, mk = kdf_ck(self.ck_recv)
        self.n_recv += 1
        detail("  Kettenschlüssel (Empfangskette)", short(old_ck))
        detail("    nächster Kettenschlüssel", short(self.ck_recv))
        line(f"Nachrichtenschlüssel (n = {header['n']})", f"{short(mk)}  (danach gelöscht)")

        # Stimmt der Prüfwert nicht (Chiffrat oder Header verändert, oder falscher Schlüssel), meldet AES-GCM InvalidTag.
        try:
            plaintext = AESGCM(mk).decrypt(nonce, ciphertext, header_aad(header))
        except InvalidTag:
            raise ValueError("Entschlüsselung fehlgeschlagen (Chiffrat oder Header verändert?)")
        del mk
        return plaintext.decode()


# --- Sicherheitsnummer -----------------------------------------------------

def fingerprint(ik_pub_1: bytes, ik_pub_2: bytes) -> str:
    # Sicherheitsnummer aus zwei öffentlichen Identitätsschlüsseln: Jeder Schlüssel wird mit SHA-256 gehasht und auf eine 30-stellige Zahl verkürzt.
    # Die beiden Zahlen werden sortiert, damit beide Partner dieselbe Nummer erhalten, und als 60 Ziffern in Fünfergruppen zusammengesetzt.
    parts = []
    for key in (ik_pub_1, ik_pub_2):
        # SHA-256-Hash des öffentlichen Schlüssels: immer 32 Bytes, egal wie der Schlüssel aussieht.
        digest = hashlib.sha256(key).digest()
        # int.from_bytes liest die 32 Bytes als eine einzige große ganze Zahl (bis zu 78 Dezimalstellen);
        # "big" heißt: das erste Byte ist das höchstwertige, wie beim Lesen einer Zahl von links nach rechts.
        # % 10**30 ist der Rest bei Division durch 10^30, also genau die letzten 30 Dezimalstellen dieser Zahl.
        number = int.from_bytes(digest, "big") % 10**30
        # str(number) macht daraus Text. Ist die Zahl kürzer als 30 Stellen (z. B. weil sie mit Nullen beginnen würde),
        # füllt zfill(30) links mit Nullen auf, damit jede Hälfte genau 30 Ziffern hat: "4711" -> "000…0004711".
        parts.append(str(number).zfill(30))
    # Sortiert die beiden Texte, die kleinere Zahl zuerst. Ohne Sortieren hätte Alice "A-Hälfte + B-Hälfte"
    # und Bob "B-Hälfte + A-Hälfte"; so erhalten beide dieselbe Reihenfolge und damit dieselbe Nummer.
    parts.sort()
    digits = parts[0] + parts[1]
    groups = []
    # Zählt in 5er-Schritten
    for start in range(0, 60, 5):
        # Zahlen von start bis start+5
        groups.append(digits[start:start + 5])
    return " ".join(groups)
