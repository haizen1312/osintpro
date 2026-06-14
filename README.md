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
- Export report stampabile, salvabile come PDF dal browser.
- Monitoraggio domini con limiti per piano.
- Cron monitor protetto da secret per rieseguire controlli in batch.
- Checkout Stripe tramite Payment Link configurabile con riferimento utente.
- Webhook Stripe firmato per attivare Pro/Agency dopo pagamento completato.
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
```

## Social OSINT

Il tab `Social` controlla passivamente la presenza pubblica di un nickname su social network e developer platform.
Genera score, profili probabili, risultati incerti, findings e percorsi Red/Purple Team per brand monitoring, anti-impersonation e due diligence.

## Prossimi step tecnici

Rendere OSINTPRO piu solido per uso continuativo:

1. Configurare definitivamente il webhook Stripe in produzione con `OSINTPRO_STRIPE_WEBHOOK_SECRET`.
2. Collegare un cron esterno o Render Cron Job a `/api/cron/monitors`.
3. Migrare SQLite a database persistente gestito per produzione lunga.
4. Aggiungere reset password e gestione account completa.
5. Alert email o webhook su cambi score, SSL e header.

## Checklist monetizzazione

Vedi `MONETIZATION.md` per la checklist pratica: Payment Link Stripe, deploy Render, pricing iniziale e primo messaggio di vendita.
