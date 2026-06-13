# Advanced Bitcoin Balance Checker

Verificatore locale sequenziale Bitcoin ad alte prestazioni, progettato per scansionare chiavi private numeriche in modo estremamente veloce e sicuro utilizzando la blockchain locale indicizzata tramite Fulcrum.

Questo progetto è un'evoluzione ottimizzata del prototipo iniziale, focalizzato sulla velocità di scansione massimizzando l'uso dell'SSD locale e minimizzando l'overhead di rete ed I/O su disco.

---

## Caratteristiche Avanzate e Ottimizzazioni

### 1. Connessione TCP Persistente (Keep-Alive)
Invece di aprire e chiudere una socket per ogni singola query, lo script apre una singola connessione TCP persistente con Fulcrum su `127.0.0.1:50001` all'avvio. La connessione viene tenuta attiva e riutilizzata continuamente, eliminando l'overhead dell'handshake TCP per ogni chiave. In caso di interruzioni di rete, lo script gestisce automaticamente la riconnessione.

### 2. Scansione in Batch JSON-RPC Multichiave
Le richieste a Fulcrum vengono raggruppate ed inviate in blocchi da **100 chiavi alla volta** (300 indirizzi totali). Fulcrum (grazie al database RocksDB posizionato su SSD) elabora le richieste parallelamente ed in modo asincrono, restituendo una singola risposta aggregata sulla socket. Questo riduce la latenza di rete locale a frazioni di millisecondo.

### 3. Checkpoint Differito (Deferred Writes)
Per evitare rallentamenti dovuti alla latenza del disco e conflitti di blocco con la sincronizzazione in tempo reale di Dropbox, il file `checkpoint.json` viene salvato in modo differito:
- Ogni **2.000 chiavi** scansionate.
- Oppure ogni **5 secondi** di esecuzione.
- **Eccezioni immediate**: Il checkpoint viene salvato all'istante se viene premuto `Ctrl+C` (SIGINT) o se viene rilevato un saldo attivo maggiore di zero.

### 4. Query di Storico On-Demand
Durante la scansione ad alta velocità viene verificato solo il saldo attivo (`blockchain.scripthash.get_balance`) dei tre indirizzi. La query sullo storico delle transazioni (`blockchain.scripthash.get_history`) viene eseguita una tantum solo sulla chiave specifica che rileva un saldo positivo, riducendo della metà il carico di query sul database di Fulcrum.

---

## Struttura del Progetto

- `advanced_checker.py`: Script di scansione ottimizzato in Python.
- `checkpoint.json`: File in cui viene registrato il progresso di scansione locale (escluso da Git via `.gitignore`).
- `risultati.json`: File contenente le chiavi WIF che possiedono un saldo attivo (escluso da Git via `.gitignore`).
- `app.log`: Registro operativo che mostra le statistiche di scansione e i warning di connessione (escluso da Git via `.gitignore`).
- `.gitignore`: Configurazione Git per escludere file locali operativi o sensibili.

---

## Requisiti di Sistema ed Infrastruttura

- Python 3.10 o versioni successive.
- Un nodo Bitcoin Core in esecuzione locale (non potato, con `txindex=1`).
- Fulcrum in esecuzione ed allineato su `127.0.0.1:50001`.

### 1. Configurazione di Bitcoin Core (`bitcoin.conf`)
Il file `bitcoin.conf` (situato nella directory dei dati di Bitcoin Core, es. `D:\Block`) deve essere configurato con i seguenti parametri abilitati:
```ini
server=1
rpcallowip=127.0.0.1
rpcport=8332
txindex=1
prune=0
dbcache=12288
```

### 2. Configurazione di Fulcrum (`fulcrum.conf`)
L'indicizzatore locale deve interfacciarsi con Bitcoin Core via RPC ed esporre il server sulla porta `50001`. Esempio di configurazione:
```ini
datadir = E:/FulcrumDB
bitcoind = 127.0.0.1:8332
rpccookie = D:/Block/.cookie

tcp = 127.0.0.1:50001
admin = 127.0.0.1:8000
stats = 127.0.0.1:8080

peering = false
announce = false
db_mem = 12288
```

### Installazione delle Dipendenze Python
Esegui nel terminale:
```powershell
pip install cryptography base58
```

---

## Come Usare il Verificatore

### 1. Test di Correttezza Matematica
Prima di avviare lo scanner reale, esegui il test di derivazione crittografica per verificare che gli indirizzi (Legacy, Nested SegWit, Native SegWit) e il WIF vengano ricavati correttamente partendo dalla chiave `1`:
```powershell
python advanced_checker.py --test-derivation
```

### 2. Avvio della Scansione ad Alta Velocità
Per avviare la scansione:
```powershell
python advanced_checker.py
```
A schermo e in `app.log` verranno visualizzate periodicamente le statistiche in tempo reale (velocità di scansione in chiavi/secondo e posizione corrente).

### 3. Comportamento in Caso di Saldo Trovato
Se lo script trova una chiave con saldo maggiore di 0 satoshi:
1. Registra tutti i dettagli, inclusa la chiave privata WIF spendibile, in `risultati.json`.
2. Aggiorna istantaneamente il checkpoint su disco registrando la chiave trovata.
3. Mostra un box di avviso di grandi dimensioni sulla console.
4. **Si arresta automaticamente** ed attende il tuo intervento. Per riprendere la scansione da dove si era fermata, basta lanciare di nuovo il comando.
