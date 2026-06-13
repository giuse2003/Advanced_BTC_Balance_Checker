import os
import sys
import json
import socket
import signal
import time
import logging
import datetime
import hashlib
import argparse

import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHECKPOINT_FILE = "checkpoint.json"
RESULTS_FILE = "risultati.json"

BATCH_SIZE = 100            # Numero di chiavi da verificare in una singola richiesta batch
CHECKPOINT_BATCH = 2000     # Salva su disco il checkpoint ogni 2000 chiavi
CHECKPOINT_TIME_SEC = 5.0   # Oppure ogni 5 secondi

keep_running = True

def handle_sigint(signum, frame):
    global keep_running
    logging.info("Rilevato segnale di arresto (Ctrl+C). Salvataggio del checkpoint in corso ed uscita pulita...")
    keep_running = False

signal.signal(signal.SIGINT, handle_sigint)

# --- Bech32 Address Encoding for P2WPKH ---
def bech32_polymod(values):
    generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (((checksum & 0x1ffffff) << 5) ^ value) & 0xffffffff
        for i in range(5):
            if (top >> i) & 1:
                checksum ^= generators[i]
    return checksum

def convert_bits(data, from_bits, to_bits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None
    return ret

def segwit_address(program):
    converted = convert_bits(program, 8, 5)
    data = [0] + converted
    expanded = [3, 3, 0, 2, 3] + data + [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(expanded) ^ 1
    checksum = []
    for i in range(6):
        checksum.append((polymod >> (5 * (5 - i))) & 31)
    return "bc1" + "".join(BECH32_CHARSET[v] for v in (data + checksum))

# --- Address and ScriptPubKey Derivation ---
def hash160(bytes_data):
    sha = hashlib.sha256(bytes_data).digest()
    h = hashlib.new('ripemd160')
    h.update(sha)
    return h.digest()

def derive_addresses_and_scripts(private_key_int):
    # Derive compressed public key
    priv_bytes = private_key_int.to_bytes(32, byteorder='big')
    priv_key_obj = ec.derive_private_key(private_key_int, ec.SECP256K1(), default_backend())
    pub_key_obj = priv_key_obj.public_key()
    compressed_pubkey = pub_key_obj.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    
    # Generate WIF (compressed)
    payload = b'\x80' + priv_bytes + b'\x01'
    wif = base58.b58encode_check(payload).decode('ascii')
    
    # 1. Legacy P2PKH
    pubkey_hash = hash160(compressed_pubkey)
    legacy_addr = base58.b58encode_check(b'\x00' + pubkey_hash).decode('ascii')
    legacy_script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
    
    # 2. Nested SegWit P2SH-P2WPKH
    redeem_script = b'\x00\x14' + pubkey_hash
    redeem_hash = hash160(redeem_script)
    nested_addr = base58.b58encode_check(b'\x05' + redeem_hash).decode('ascii')
    nested_script = b'\xa9\x14' + redeem_hash + b'\x87'
    
    # 3. Native SegWit P2WPKH
    native_addr = segwit_address(pubkey_hash)
    native_script = b'\x00\x14' + pubkey_hash
    
    # Convert scriptPubKeys to Electrum scripthashes
    scripthash_legacy = hashlib.sha256(legacy_script).digest()[::-1].hex()
    scripthash_nested = hashlib.sha256(nested_script).digest()[::-1].hex()
    scripthash_native = hashlib.sha256(native_script).digest()[::-1].hex()
    
    return {
        "wif": wif,
        "addresses": {
            "legacy": legacy_addr,
            "nested": nested_addr,
            "native": native_addr
        },
        "scripthashes": {
            "legacy": scripthash_legacy,
            "nested": scripthash_nested,
            "native": scripthash_native
        }
    }

# --- Persistent Fulcrum TCP Client ---
class FulcrumClient:
    def __init__(self, host="127.0.0.1", port=50001):
        self.host = host
        self.port = port
        self.sock = None
        self.sock_file = None
        
    def connect(self):
        self.close()
        self.sock = socket.create_connection((self.host, self.port), timeout=15)
        # file wrapper in modalità lettura testo con buffering di riga
        self.sock_file = self.sock.makefile('r', encoding='utf-8')
        
    def close(self):
        if self.sock_file:
            try:
                self.sock_file.close()
            except:
                pass
            self.sock_file = None
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            
    def send_batch(self, reqs):
        if not self.sock:
            self.connect()
        try:
            payload = json.dumps(reqs) + "\n"
            self.sock.sendall(payload.encode('utf-8'))
            
            line = self.sock_file.readline()
            if not line:
                raise Exception("Connessione chiusa dal server durante la ricezione.")
            return json.loads(line)
        except Exception as e:
            self.close()
            raise e

    def query_history(self, scripthashes):
        # Metodo helper sincrono per raccogliere lo storico di una chiave trovata
        reqs = []
        keys = ["legacy", "nested", "native"]
        for i, key in enumerate(keys):
            reqs.append({
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.get_history",
                "params": [scripthashes[key]],
                "id": i + 1000
            })
        
        try:
            resps = self.send_batch(reqs)
            resps.sort(key=lambda r: r.get("id", 0))
            return {
                "legacy": len(resps[0]["result"]) if isinstance(resps[0]["result"], list) else 0,
                "nested": len(resps[1]["result"]) if isinstance(resps[1]["result"], list) else 0,
                "native": len(resps[2]["result"]) if isinstance(resps[2]["result"], list) else 0
            }
        except Exception as e:
            logging.error(f"Errore durante la query dello storico dettagliato: {e}")
            return {"legacy": 0, "nested": 0, "native": 0}

# --- Atomic & Lock-Resilient File Writing ---
def safe_write_json(file_path, data):
    tmp_file = file_path + ".tmp"
    for attempt in range(15):
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_file, file_path)
            return
        except (PermissionError, OSError):
            if attempt == 14:
                raise
            time.sleep(0.1)

def write_checkpoint(checkpoint):
    safe_write_json(CHECKPOINT_FILE, checkpoint)

# --- Results Management ---
def save_positive_match(private_key_int, wif, addresses, fulcrum_data):
    results = []
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, "r", encoding="utf-8") as f:
                results = json.load(f)
        except Exception as e:
            logging.error(f"Errore nella lettura del file risultati: {e}. Verrà sovrascritto.")
            
    match_entry = {
        "private_key_number": str(private_key_int),
        "wif": wif,
        "addresses": addresses,
        "results": fulcrum_data,
        "found_at": datetime.datetime.now().isoformat()
    }
    results.append(match_entry)
    safe_write_json(RESULTS_FILE, results)
    logging.info(f"!!! TROVATO SALDO ATTIVO !!! Salvato in {RESULTS_FILE}")

def load_checkpoint():
    if not os.path.exists(CHECKPOINT_FILE):
        initial = {
            "last_completed_private_key_number": "0",
            "next_private_key_number": "1",
            "checked_keys": "0",
            "updated_at": None
        }
        write_checkpoint(initial)
        return initial
        
    try:
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Impossibile leggere il checkpoint: {e}. Ne creo uno nuovo.")
        initial = {
            "last_completed_private_key_number": "0",
            "next_private_key_number": "1",
            "checked_keys": "0",
            "updated_at": None
        }
        write_checkpoint(initial)
        return initial

# --- Main Program Execution ---
def main():
    parser = argparse.ArgumentParser(description="Verificatore Bitcoin locale ottimizzato ad alte prestazioni.")
    parser.add_argument("--test-derivation", action="store_true", help="Esegue un test di derivazione crittografica ed esce.")
    args = parser.parse_args()
    
    if args.test_derivation:
        logging.info("Avvio del test di derivazione per la chiave numerica 1...")
        derived = derive_addresses_and_scripts(1)
        expected_legacy = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        expected_nested = "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        expected_native = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        
        logging.info(f"WIF derivato: {derived['wif']}")
        logging.info(f"Legacy: {derived['addresses']['legacy']} (Atteso: {expected_legacy})")
        logging.info(f"Nested: {derived['addresses']['nested']} (Atteso: {expected_nested})")
        logging.info(f"Native: {derived['addresses']['native']} (Atteso: {expected_native})")
        
        assert derived['addresses']['legacy'] == expected_legacy, "Errore Legacy!"
        assert derived['addresses']['nested'] == expected_nested, "Errore Nested!"
        assert derived['addresses']['native'] == expected_native, "Errore Native!"
        
        logging.info("Test di derivazione superato con successo!")
        sys.exit(0)
        
    logging.info("Avvio dell'Advanced Bitcoin Balance Checker...")
    checkpoint = load_checkpoint()
    
    next_key = int(checkpoint["next_private_key_number"])
    checked_keys = int(checkpoint["checked_keys"])
    
    logging.info(f"Ripresa dal checkpoint: prossima chiave da verificare = {next_key}, chiavi già verificate = {checked_keys}")
    
    client = FulcrumClient()
    
    # Variabili in memoria per ottimizzare la scrittura del checkpoint su disco
    last_saved_key = next_key
    last_saved_time = time.time()
    
    # Statistiche di sessione
    session_start_time = time.time()
    session_checked_keys = 0
    
    while keep_running:
        # 1. Prepara il batch di BATCH_SIZE chiavi
        batch_keys = []
        batch_requests = []
        
        for offset in range(BATCH_SIZE):
            current_key = next_key + offset
            derived = derive_addresses_and_scripts(current_key)
            batch_keys.append((current_key, derived))
            
            # Aggiunge le richieste al batch JSON-RPC (solo get_balance per massima velocità)
            for addr_index, addr_type in enumerate(["legacy", "nested", "native"]):
                sh = derived["scripthashes"][addr_type]
                batch_requests.append({
                    "jsonrpc": "2.0",
                    "method": "blockchain.scripthash.get_balance",
                    "params": [sh],
                    # ID mappa: offset della chiave * 3 + indice indirizzo
                    "id": offset * 3 + addr_index
                })
                
        # 2. Interroga Fulcrum locale via TCP (con riconnessione automatica e riprove)
        batch_responses = None
        while keep_running and batch_responses is None:
            try:
                batch_responses = client.send_batch(batch_requests)
            except Exception as e:
                logging.warning(f"Errore di connessione a Fulcrum durante l'interrogazione batch ({next_key}-{next_key+BATCH_SIZE-1}): {e}. Riprovo tra 10 secondi...")
                client.close()
                for _ in range(10):
                    if not keep_running:
                        break
                    time.sleep(1)
                    
        if not keep_running:
            break
            
        # 3. Ordina le risposte in base all'ID
        batch_responses.sort(key=lambda r: r.get("id", 0))
        
        # 4. Analizza i saldi del batch
        found_funds = False
        fund_key_info = None
        
        for offset, (current_key, derived) in enumerate(batch_keys):
            legacy_bal = batch_responses[offset * 3]["result"]
            nested_bal = batch_responses[offset * 3 + 1]["result"]
            native_bal = batch_responses[offset * 3 + 2]["result"]
            
            # Calcola saldo totale confermato + unconfermed
            total_legacy = legacy_bal.get("confirmed", 0) + legacy_bal.get("unconfirmed", 0)
            total_nested = nested_bal.get("confirmed", 0) + nested_bal.get("unconfirmed", 0)
            total_native = native_bal.get("confirmed", 0) + native_bal.get("unconfirmed", 0)
            
            total_sats = total_legacy + total_nested + total_native
            
            if total_sats > 0:
                found_funds = True
                fund_key_info = {
                    "number": current_key,
                    "wif": derived["wif"],
                    "addresses": derived["addresses"],
                    "scripthashes": derived["scripthashes"],
                    "balances": {
                        "legacy": legacy_bal,
                        "nested": nested_bal,
                        "native": native_bal
                    }
                }
                break # Interrompe l'analisi del batch alla prima chiave con fondi
                
        # 5. Gestione nel caso in cui venga trovato un saldo attivo
        if found_funds:
            # Query dello storico per la chiave vincente (richiesta di rete aggiuntiva una tantum)
            history_counts = client.query_history(fund_key_info["scripthashes"])
            
            # Combina i dati per il salvataggio
            fulcrum_save_data = {}
            for addr_type in ["legacy", "nested", "native"]:
                bal = fund_key_info["balances"][addr_type]
                fulcrum_save_data[addr_type] = {
                    "confirmed": bal.get("confirmed", 0),
                    "unconfirmed": bal.get("unconfirmed", 0),
                    "history_count": history_counts[addr_type]
                }
                
            save_positive_match(fund_key_info["number"], fund_key_info["wif"], fund_key_info["addresses"], fulcrum_save_data)
            
            # Salva il checkpoint aggiornando la posizione alla chiave trovata
            checkpoint_update = {
                "last_completed_private_key_number": str(fund_key_info["number"]),
                "next_private_key_number": str(fund_key_info["number"] + 1),
                "checked_keys": str(checked_keys + offset + 1),
                "updated_at": datetime.datetime.now().isoformat()
            }
            write_checkpoint(checkpoint_update)
            client.close()
            
            logging.info("======================================================================")
            logging.info(f"!!! RILEVATO SALDO ATTIVO SULLA CHIAVE #{fund_key_info['number']} !!!")
            logging.info(f"Saldo: {sum(b.get('confirmed', 0) + b.get('unconfirmed', 0) for b in fund_key_info['balances'].values())} sat")
            logging.info("Lo script è stato INTERROTTO per attendere il tuo intervento.")
            logging.info("Puoi ispezionare il file risultati.json per tutti i dettagli.")
            logging.info("======================================================================")
            break
            
        # 6. Avanza la posizione del batch
        next_key += BATCH_SIZE
        checked_keys += BATCH_SIZE
        session_checked_keys += BATCH_SIZE
        
        # 7. Scrittura del checkpoint differito (ottimizzazione I/O)
        current_time = time.time()
        if (next_key - last_saved_key >= CHECKPOINT_BATCH) or (current_time - last_saved_time >= CHECKPOINT_TIME_SEC):
            checkpoint_update = {
                "last_completed_private_key_number": str(next_key - 1),
                "next_private_key_number": str(next_key),
                "checked_keys": str(checked_keys),
                "updated_at": datetime.datetime.now().isoformat()
            }
            write_checkpoint(checkpoint_update)
            last_saved_key = next_key
            last_saved_time = current_time
            
            # Stampa log periodico delle performance di scansione
            elapsed = current_time - session_start_time
            speed = session_checked_keys / elapsed if elapsed > 0 else 0
            logging.info(f"Scansionate: {checked_keys} chiavi totali | Velocità: {speed:.1f} chiavi/sec | Posizione corrente: #{next_key}")

    # All'uscita della scansione (es. premuto Ctrl+C), salva sempre lo stato esatto
    if not found_funds:
        checkpoint_update = {
            "last_completed_private_key_number": str(next_key - 1),
            "next_private_key_number": str(next_key),
            "checked_keys": str(checked_keys),
            "updated_at": datetime.datetime.now().isoformat()
        }
        write_checkpoint(checkpoint_update)
        client.close()
        logging.info("Programma arrestato ordinatamente. Stato di checkpoint salvato con successo.")

if __name__ == "__main__":
    main()
