# Scorte di casa

Gestione delle scorte domestiche con account personali: anagrafica articoli, inventario, consumi e lista della spesa generata dalla scorta minima di ogni articolo. Ogni utente vede solo i propri dati. Nella scheda Aspetto si scelgono tema (automatico, chiaro, scuro) e colore, salvati sul dispositivo.

## Avvio

Serve solo Python 3.8 o successivo, nessuna dipendenza da installare.

    python3 app.py

Apri http://localhost:8000 e crea il primo account. Da un telefono nella stessa rete wifi usa l'indirizzo IP del computer.

## Variabili d'ambiente

| Nome | Significato |
| --- | --- |
| `PORT` | porta del server (default 8000) |
| `HOST` | `127.0.0.1` per accettare solo connessioni locali (default `0.0.0.0`) |
| `DB_PATH` | percorso del file SQLite (default `scorte.db` accanto ad `app.py`) |
| `REGISTRAZIONE_APERTA` | `1` per permettere a chiunque di creare un account. Senza, si può creare solo il primo account |
| `COOKIE_SECURE` | `1` per forzare il cookie di sessione solo su HTTPS (è attivo da solo se il proxy invia `X-Forwarded-Proto: https`) |

## Sicurezza

Le password sono salvate con scrypt e un sale casuale, le sessioni durano 30 giorni con cookie HttpOnly, e dopo 5 tentativi falliti l'accesso è bloccato per 10 minuti. Il traffico però non è cifrato dall'app: se la pubblichi su internet mettila dietro HTTPS (lo forniscono di norma i servizi di hosting).

## Pubblicazione

GitHub conserva il codice ma non esegue app Python: GitHub Pages serve solo siti statici. Per usarla da internet serve un servizio che esegua Python e abbia un disco persistente per il file `scorte.db` (altrimenti i dati si perdono a ogni riavvio).

## Come funziona

- La giacenza di un articolo è la somma dei suoi movimenti (aggiunte, consumi, conteggi). Il conteggio dell'inventario registra la differenza tra quanto conti e quanto risultava.
- Un articolo finisce nella lista della spesa quando la giacenza scende sotto la scorta minima. La quantità proposta è la differenza fino al minimo.
- Per il backup basta copiare `scorte.db`.
