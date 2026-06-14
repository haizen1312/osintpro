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
- Account email/password con hash PBKDF2 e cookie HTTP-only.
- Crediti Free salvati lato server, non piu in `localStorage`.
- Cookie demo HTTP-only per distinguere workspace anonimi.
- Storico report persistente lato server.
- Export CSV dello storico.
- Export report stampabile, salvabile come PDF dal browser.
- Monitoraggio domini con limiti per piano.
- Checkout Stripe tramite Payment Link configurabile.
- Simulazione upgrade Pro/Agency per validare UX e packaging.
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

- Free: 5 report e 1 dominio monitorato.
- Pro: 19 EUR/mese, report illimitati e 5 domini monitorati.
- Agency: 79 EUR/mese, report per clienti e 25 domini monitorati.

Per collegare Stripe senza cambiare codice, crea due Payment Link su Stripe e avvia il server con:

```bash
OSINTPRO_STRIPE_PRO_URL="https://buy.stripe.com/..." \
OSINTPRO_STRIPE_AGENCY_URL="https://buy.stripe.com/..." \
python3 server.py
```

In locale puoi usare i bottoni `Demo Pro` e `Demo Agency` per testare il paywall senza pagamento reale.

## Accesso admin privato

La pagina admin non e linkata nella UI pubblica:

```text
http://127.0.0.1:8765/admin.html
```

Codice locale predefinito:

```text
leonardo-admin
```

Per deploy o demo pubbliche, cambialo sempre con una variabile ambiente:

```bash
OSINTPRO_ADMIN_CODE="codice-lungo-segreto" python3 server.py
```

L'accesso admin porta il workspace corrente al piano `Admin`: report illimitati, monitor illimitati e nessun checkout richiesto.

## Metterlo online senza comprare dominio

GitHub serve per ospitare il codice e collegare deploy automatici. GitHub Pages non basta per questa app, perche Pages pubblica HTML/CSS/JS statici e non esegue il backend Python con API e SQLite.

Percorso consigliato a zero dominio:

1. Crea un repository GitHub privato o pubblico.
2. Pusha questo progetto.
3. Crea un Web Service su Render collegato al repository GitHub.
4. Usa il blueprint `render.yaml` oppure configura:
   - Build command: `pip install -r requirements.txt`
   - Start command: `python3 server.py --host 0.0.0.0 --port $PORT`
   - Health check: `/api/health`
5. Imposta env var:
   - `OSINTPRO_ADMIN_CODE`
   - `OSINTPRO_SECRET_KEY`
   - `OSINTPRO_STRIPE_PRO_URL`
   - `OSINTPRO_STRIPE_AGENCY_URL`

Render assegna un sottodominio `onrender.com`, quindi puoi validare e vendere senza comprare dominio. Un dominio custom arriva dopo, quando hai i primi utenti o le prime agency interessate.

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

1. Sostituire la sessione demo con auth reale via email magic link o OAuth.
2. Stripe Checkout Sessions e webhook per attivare i piani dopo pagamento reale.
3. Job schedulati per monitorare domini nel tempo.
4. Alert email su cambi score, SSL e header.
5. Deploy con dominio custom.

## Checklist monetizzazione

Vedi `MONETIZATION.md` per la checklist pratica: Payment Link Stripe, deploy Render, pricing iniziale e primo messaggio di vendita.
