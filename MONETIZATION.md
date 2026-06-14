# OSINTPRO Monetization Checklist

OSINTPRO va venduto come intelligence passiva per domini, brand e nickname pubblici.
Non posizionarlo come scanner offensivo: il valore e nel report, nel monitoraggio e nella priorita dei finding.

Sito live:

```text
https://osintpro-48j4.onrender.com/
```

## Offerta iniziale

- Free tier: 5 report iniziali, 1 dominio monitorato.
- Pro: 19 EUR/mese, report illimitati, 5 domini monitorati, PDF/CSV.
- Agency: 79 EUR/mese, report per clienti, 25 domini monitorati, workflow Red/Purple Team e segnali OSINT avanzati.

## Primo setup Stripe

1. Crea due Payment Link su Stripe:
   - OSINTPRO Pro, 19 EUR/mese.
   - OSINTPRO Agency, 79 EUR/mese.
2. Copia gli URL dei Payment Link.
3. In produzione imposta:

```bash
OSINTPRO_STRIPE_PRO_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_AGENCY_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_WEBHOOK_SECRET="whsec_..."
```

Questa versione usa Payment Link per validare vendite subito. Il backend aggiunge un `client_reference_id` al link Stripe, quindi il webhook `checkout.session.completed` puo riconciliare pagamento, utente e piano.

Webhook da creare in Stripe:

```text
https://osintpro-48j4.onrender.com/api/stripe/webhook
```

## Primo canale di vendita

Target iniziali:

- piccole agenzie web
- freelance cyber/GDPR
- founder SaaS
- e-commerce con dominio principale e brand social

Messaggio breve:

```text
Ti preparo un mini report OSINT passivo sul tuo dominio: DNS, TLS, email security, header, brand exposure e raccomandazioni pratiche.
Se vuoi monitoraggio mensile, PDF per clienti, DNSSEC/BIMI review e controllo takeover da CNAME pubblici, OSINTPRO parte da 19 EUR/mese.
```

## Cose da non promettere

- Nessuna garanzia di sicurezza assoluta.
- Nessun exploit o scansione aggressiva.
- Nessuna attribuzione certa sui nickname senza verifica manuale.

## Prossimi upgrade che aumentano il prezzo

- database persistente gestito
- alert webhook su cambiamenti monitor
- export PDF vero server-side
- workspace agency multi-cliente
- metriche admin avanzate e backup operativo
- audit finale prima di rendere pubblico il repository
