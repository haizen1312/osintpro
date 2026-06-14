# OSINTPRO

OSINTPRO e un SaaS freemium per intelligence passiva su domini, brand e nickname pubblici.

## Sito live

```text
https://osintpro-48j4.onrender.com/
```

Apri il sito live, crea un account con nickname/password e prova:

- Domain OSINT su un dominio pubblico.
- Social OSINT su un nickname pubblico.
- Report PDF/CSV.
- Monitoring domini.
- Upgrade Pro/Agency tramite Stripe.

Analizza domini usando raccolta passiva:

- DNS/IP resolution
- record A/AAAA/MX/NS/TXT/CAA/SOA tramite `dig`, se disponibile
- certificato HTTPS
- security header pubblici
- scoring sintetico del dominio
- RDAP/registrar pubblico
- postura email: SPF, DMARC, MTA-STS, TLS-RPT
- well-known pubblici: security.txt, robots.txt, sitemap.xml
- Certificate Transparency per nomi e sottodomini osservabili
- fingerprint tecnologico passivo da header e segnali web
- ipotesi di vulnerabilita derivate da evidenze passive
- DNSSEC, BIMI, well-known account/security endpoints
- CNAME review da subdomini Certificate Transparency per possibili takeover da verificare
- percorsi red team autorizzati e controlli purple team consigliati

OSINTPRO non esegue exploit, brute force o scansioni aggressive. Le sezioni Red/Purple Team trasformano segnali pubblici in ipotesi, priorita e controlli operativi vendibili a clienti o agency.

## Stato prodotto

- App pubblicata su Render.
- Repository GitHub collegato al deploy automatico.
- API Python con endpoint health, sessione, analisi e report.
- Database SQLite in `data/osintpro.sqlite3`.
- Account nickname/password con hash PBKDF2 e cookie HTTP-only.
- Crediti Free salvati lato server, non piu in `localStorage`.
- Cookie HTTP-only per distinguere workspace anonimi prima della registrazione.
- Storico report persistente lato server.
- Storici visibili solo dopo login e isolati per account.
- Cancellazione storico domini, social o completa per ogni account.
- Export CSV dello storico.
- Export admin sanitizzato per backup operativo senza password hash o secret.
- Export report stampabile, salvabile come PDF dal browser.
- Monitoraggio domini con limiti per piano.
- Cron monitor protetto da secret per rieseguire controlli in batch.
- Workflow GitHub Actions giornaliero per richiamare il cron monitor in produzione.
- Alert webhook opzionale quando un monitor cambia o va in errore.
- Path database configurabile via env per storage persistente.
- Limite anti multi-account Free basato su fingerprint hashato della connessione.
- Checkout Stripe tramite Payment Link configurabile con riferimento utente.
- Webhook Stripe firmato per attivare Pro/Agency dopo pagamento completato.
- Pannello operativo privato per stato produzione, utenti, piani e ultimi eventi Stripe.
- Pagina Social OSINT per analizzare nickname pubblici su social/dev platform.

## Avvio locale

```bash
python3 server.py
```

Poi apri:

```text
http://127.0.0.1:8765
```

Il database viene creato automaticamente al primo avvio.
Per usare un path persistente:

```bash
OSINTPRO_DB_PATH="/path/persistente/osintpro.sqlite3" python3 server.py
```

Il deploy pubblico usa Render:

```text
https://osintpro-48j4.onrender.com/
```

## Monetizzazione

Piani implementati nella UI:

- Free tier: 5 report iniziali e 1 dominio monitorato.
- Pro: 19 EUR/mese, report illimitati e 5 domini monitorati.
- Agency: 79 EUR/mese, report per clienti e 25 domini monitorati.

In produzione Stripe e configurato tramite variabili ambiente. In locale puoi usare:

```bash
OSINTPRO_STRIPE_PRO_URL="https://buy.stripe.com/..." \
OSINTPRO_STRIPE_AGENCY_URL="https://buy.stripe.com/..." \
OSINTPRO_STRIPE_WEBHOOK_SECRET="whsec_..." \
python3 server.py
```

Endpoint webhook:

```text
https://osintpro-48j4.onrender.com/api/stripe/webhook
```

Evento Stripe da collegare:

```text
checkout.session.completed
```

Il Free tier serve per valutare il prodotto. L'uso continuativo e il monitoraggio esteso sono pensati per i piani Pro e Agency.

## Export PDF

Ogni report ha un link `PDF`. Si apre una pagina HTML pulita e stampabile: dal browser usa `Salva come PDF`.
Questo e il primo artefatto vendibile per agenzie e consulenti.

## Monitoring

Il tab `Monitoring` salva domini in SQLite e `Run checks` riesegue le analisi passive.
In produzione il cron puo richiamare:

```bash
curl -X POST "https://<host>/api/cron/monitors" \
  -H "Authorization: Bearer $OSINTPRO_CRON_SECRET"
```

Variabili:

```text
OSINTPRO_CRON_SECRET
OSINTPRO_MONITOR_BATCH_LIMIT=20
OSINTPRO_REGISTRATION_IP_LIMIT=3
OSINTPRO_REGISTRATION_IP_ALLOWLIST="203.0.113.10,198.51.100.0/24"
```

Il secret cron e configurato in produzione. Il repository include anche un workflow GitHub Actions giornaliero in `.github/workflows/monitor-cron.yml`.

`OSINTPRO_REGISTRATION_IP_ALLOWLIST` e opzionale e serve per escludere connessioni fidate dal limite anti multi-account.

## Alert webhook

Per ricevere alert su cambi monitor:

```text
OSINTPRO_ALERT_WEBHOOK_URL="https://example.com/webhook"
```

Eventi inviati:

- `monitor.changed`
- `monitor.error`

## Social OSINT

Il tab `Social` controlla passivamente la presenza pubblica di un nickname su social network e developer platform.
Genera score, profili probabili, risultati incerti, findings e percorsi Red/Purple Team per brand monitoring, anti-impersonation e due diligence.

## Prossimi step tecnici

Rendere OSINTPRO piu solido per uso continuativo:

1. Migrare SQLite a database persistente gestito per produzione lunga.
2. Aggiungere reset password se si introduce un canale di recupero account.
3. Workspace agency multi-cliente.
4. Audit finale prima di rendere il repository pubblico.

## Checklist monetizzazione

Vedi `MONETIZATION.md` per la checklist pratica: Payment Link Stripe, deploy Render, pricing iniziale e primo messaggio di vendita.
