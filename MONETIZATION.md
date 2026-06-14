# OSINTPRO Monetization Checklist

OSINTPRO va venduto come intelligence passiva per domini, brand e nickname pubblici.
Non posizionarlo come scanner offensivo: il valore e nel report, nel monitoraggio e nella priorita dei finding.

## Offerta iniziale

- Free: 5 report, 1 dominio monitorato.
- Pro: 19 EUR/mese, report illimitati, 5 domini monitorati, PDF/CSV.
- Agency: 79 EUR/mese, report per clienti, 25 domini monitorati, workflow Red/Purple Team.

## Primo setup Stripe

1. Crea due Payment Link su Stripe:
   - OSINTPRO Pro, 19 EUR/mese.
   - OSINTPRO Agency, 79 EUR/mese.
2. Copia gli URL dei Payment Link.
3. In produzione imposta:

```bash
OSINTPRO_STRIPE_PRO_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_AGENCY_URL="https://buy.stripe.com/..."
```

Questa versione usa Payment Link per validare vendite subito.
Il passo successivo e Stripe Checkout Sessions con webhook per attivare automaticamente il piano dopo pagamento reale.

## Deploy senza comprare dominio

1. Crea repository GitHub `osintpro`.
2. Pusha il codice.
3. Apri Render e crea un Web Service dal repository.
4. Usa `render.yaml` oppure:
   - Build command: `pip install -r requirements.txt`
   - Start command: `python3 server.py --host 0.0.0.0 --port $PORT`
   - Health check: `/api/health`
5. Imposta queste variabili ambiente:
   - `OSINTPRO_ADMIN_CODE`
   - `OSINTPRO_SECRET_KEY`
   - `OSINTPRO_STRIPE_PRO_URL`
   - `OSINTPRO_STRIPE_AGENCY_URL`

Render assegna un URL `onrender.com`, sufficiente per prime demo e primi clienti.

## Primo canale di vendita

Target iniziali:

- piccole agenzie web
- freelance cyber/GDPR
- founder SaaS
- e-commerce con dominio principale e brand social

Messaggio breve:

```text
Ti preparo gratis un mini report OSINT passivo sul tuo dominio: DNS, TLS, email security, header, brand exposure e raccomandazioni pratiche.
Se vuoi monitoraggio mensile e report PDF per clienti, OSINTPRO parte da 19 EUR/mese.
```

## Cose da non promettere

- Nessuna garanzia di sicurezza assoluta.
- Nessun exploit o scansione aggressiva.
- Nessuna attribuzione certa sui nickname senza verifica manuale.

## Prossimi upgrade che aumentano il prezzo

- webhook Stripe per attivare piani automaticamente
- cron giornaliero per monitor
- alert email su cambiamenti
- export PDF vero server-side
- workspace agency multi-cliente
- dashboard admin utenti/piani
