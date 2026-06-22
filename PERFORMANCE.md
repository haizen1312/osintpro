# OSINTPRO Performance Notes

## Current Guardrails

- Threaded HTTP server for concurrent lightweight requests.
- SQLite WAL mode and a five-second busy timeout.
- Database connections close at the end of every transaction.
- Anonymous sessions retain only the latest report per report type.
- Repository Audit Lab limits files, file size and total text payload.
- Passive network requests use bounded timeouts and response sizes.
- Animated background pauses during scrolling and supports Eco mode.

## Export Performance

PDF and CSV files are generated in memory because current reports are small.
Every response includes an exact `Content-Length` and attachment filename.

Do not add large binary assets to the current PDF renderer. When report size
or usage grows, stream exports or generate them asynchronously with a bounded
job queue.

## Measurements To Add

1. Endpoint latency by route and status.
2. Export size and generation duration.
3. SQLite lock and retry counts.
4. Provider timeout and error rates.
5. Repository audit file count, bytes and rule duration.

## Upgrade Triggers

Move beyond the current process when:

- paid users depend on durable history,
- concurrent monitor runs create SQLite lock pressure,
- report exports regularly exceed a few megabytes,
- background jobs delay interactive requests,
- API usage needs horizontal scaling.
