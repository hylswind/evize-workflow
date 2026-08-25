"""The only place boto3 calls live.

One module per service. Every function takes an already-built client so callers
choose the credentials, and every wait takes injected sleep/now so tests run
offline and instantly. Both phases share these modules, which is why the
per-module real-account tests only have to run once per service.
"""
