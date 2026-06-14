# OSINTPRO SaaS Seed

OSINTPRO e una base SaaS freemium per intelligence passiva su domini e brand.
La versione attuale resta leggera e locale, ma ha gia una prima separazione tra frontend, API e stato lato server.

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
- percorsi red team autorizzati e controlli purple team consigliati

OSINTPRO non esegue exploit, brute force o scansioni aggressive. Le sezioni Red/Purple Team trasformano segnali pubblici in ipotesi, priorita e controlli operativi vendibili a clienti o agency.

## Stato prodotto

- API Python locale con endpoint health, sessione, analisi e report.
- Database SQLite in `data/osintpro.sqlite3`.
- Account nickname/password con hash PBKDF2 e cookie HTTP-only.
- Crediti Free salvati lato server, non piu in `localStorage`.
- Cookie HTTP-only per distinguere workspace anonimi prima della registrazione.
- Storico report persistente lato server.
- Export CSV dello storico.
- Export report stampabile, salvabile come PDF dal browser.
- Monitoraggio domini con limiti per piano.
- Checkout Stripe tramite Payment Link configurabile con riferimento utente.
- Webhook Stripe firmato per attivare Pro/Agency dopo pagamento completato.
- Pagina Social OSINT per analizzare nickname pubblici su social/dev platform.

## Avvio

```bash
python3 server.py
```

Poi apri:

```text
http://127.0.0.1:8765
```

Il database viene creato automaticamente al primo avvio.

## Monetizzazione

Piani implementati nella UI:

- Free tier: 5 report iniziali e 1 dominio monitorato.
- Pro: 19 EUR/mese, report illimitati e 5 domini monitorati.
- Agency: 79 EUR/mese, report per clienti e 25 domini monitorati.

Per collegare Stripe senza cambiare codice, crea due Payment Link su Stripe e avvia il server con:

```bash
OSINTPRO_STRIPE_PRO_URL="https://buy.stripe.com/..." \
OSINTPRO_STRIPE_AGENCY_URL="https://buy.stripe.com/..." \
OSINTPRO_STRIPE_WEBHOOK_SECRET="whsec_..." \
python3 server.py
```

Endpoint webhook:

```text
https://<host>/api/stripe/webhook
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
In produzione questo endpoint va richiamato da un cron giornaliero.

## Social OSINT

Il tab `Social` controlla passivamente la presenza pubblica di un nickname su social network e developer platform.
Genera score, profili probabili, risultati incerti, findings e percorsi Red/Purple Team per brand monitoring, anti-impersonation e due diligence.

## Prossimo passo tecnico

Trasformare questa seed app in SaaS deployabile:

1. Configurare il webhook Stripe in produzione con `OSINTPRO_STRIPE_WEBHOOK_SECRET`.
2. Aggiungere reset password e gestione account completa.
3. Job schedulati per monitorare domini nel tempo.
4. Alert email o webhook su cambi score, SSL e header.
5. Migrare SQLite a database persistente gestito per produzione lunga.

## Checklist monetizzazione

Vedi `MONETIZATION.md` per la checklist pratica: Payment Link Stripe, deploy Render, pricing iniziale e primo messaggio di vendita.
