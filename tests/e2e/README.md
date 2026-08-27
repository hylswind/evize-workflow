# The end-to-end run

Everything else about enclavize is tested against moto, hand-written fakes, or a
scratch account that cleans up after itself. What is left needs a real account
sealed for real:

- `gh attestation verify --signer-workflow` actually holding — the trust anchor,
  and nothing short of a real Sigstore certificate exercises it
- accepting a domain transfer, which moves a real domain when it works
- the sign-in lock closing the console while never touching signed API calls
- a certificate validating through DNS, and two distributions plus a custom
  domain serving three names
- the two parallel phases meeting on a bucket name each derives independently
- the permission boundary as IAM enforces it, rather than as a policy document
  describes it
- the state machine indexing its own applies — a listing, an intrinsic and a
  catch, none of which a definition being valid says anything about

**Not proven here: the event-history audit.** Every run in this suite passes
`bypass_event_check=true`, because it keeps a way back into the account and the
audit is built to refuse exactly that — a second root key shows up as a second
`CreateAccessKey` where it permits one, an admin IAM user as an `iam:CreateUser`
on no allow-list. The audit is covered offline in `tests/test_verdict.py`,
against a real account's dumped history.

## Nothing here is tied to one caller or one application

Point it at your own by writing a profile. The suite reads what it can rather
than being told: which reusable workflow signs, and at what ref, comes from the
caller's own workflow file, so it cannot disagree with what really runs.

### What a caller must look like

Checked by `preflight.py` before anything is dispatched:

- a `workflow_dispatch` trigger accepting `domain`, `start`, `repo`,
  `bypass_event_check` and `bypass_domain_transfer`
- exactly one job with a `uses:` naming a reusable workflow at a pinned ref
- that job granting `id-token: write`, `attestations: write`, `contents: read`
- every secret it passes down actually set on the repository

### What an application must look like

**One thing: an executable `setup.sh` at the repository root.** That is all
enclavize requires, and the core of stage 3 checks no more than that — post a
commit, an instance runs that script.

Three optional additions let the suite check more, and each is skipped when the
profile omits it:

| profile key | what it adds |
|---|---|
| `app.url` | a URL polled until it answers after the commit is applied |
| `app.resultsUrl` | a JSON document of the application's own checks |
| `app.teardown` | a script `unseal.py` runs to remove what it created |

`app.resultsUrl` should serve:

```json
{"ok": true,
 "commit": "473542a6bdbec74ee3b52e8809b034f72b5ba7cf",
 "probes": [{"name": "read the proof bucket", "expected": "deny",
             "verdict": "ok", "detail": "AccessDenied ..."}]}
```

Every probe must have `verdict: "ok"`. For an application that probes the
permission boundary from inside the sealed account, this is the only place in
the whole project where IAM itself answers — everywhere else the boundary is
asserted against a document, which says what should happen rather than what did.

`commit` is optional but worth serving. An application that replaces itself
keeps answering with the previous deploy's results until the new one is ready,
and those would satisfy the check at once — reporting a pass for work that had
not run. Naming the commit lets the suite hold out for the right results.

## Before the first cycle

1. A spare AWS account holding the domain.
2. A freshly signed-up account to enclavize, using an address at that domain,
   with IAM billing access enabled.
3. **A way back in that outlives the seal.** Two shapes work:
   - an **admin IAM user** created before the run, with no permissions
     boundary. Easier, because the workflow deletes the root key it is handed
     and a CLI configured with a separate user is unaffected by that churn.
   - a **second root key**. AWS allows exactly two per user, root included, so
     the loop sits at that limit: one is spent, one is kept. Set `rescueKeyId`
     in the profile and preflight can then tell them apart.

   Either way, without one the account is spent after a single run.
4. **A root key for the workflow to spend**, set as `ROOT_KEY_ID`. If your way
   back in is an IAM user, this can be the key your CLI used to use.
5. `profiles/mine.yml`, copied from `example.yml`. Everything in `profiles/` is
   gitignored except the example.
6. The caller's five secrets set.

### What an IAM user cannot see

Only root can enumerate root's access keys — from any other identity there is
no API for it, and `list_access_keys` answers about the *caller* instead, which
is a worse failure than an error. `GetAccountSummary` offers only
`AccountAccessKeysPresent`, a flag rather than a count, so it reads the same
whether root holds one key or two.

So running as an IAM user, the suite checks that root still has *a* key and
skips the rest, saying so. Confirm by hand that the workflow's key is gone and
your way back in is not.

## A cycle

```sh
export ENCLAVIZE_E2E=1
export ENCLAVIZE_E2E_PROFILE=tests/e2e/profiles/mine.yml
export ENCLAVIZE_TEST_ACCOUNTS=111122223333
export ENCLAVIZE_APPLY_API_KEY=...
export ENCLAVIZE_CONSOLE_ZIP_PASSWORD=...      # optional
export AWS_PROFILE=...                          # root, or your admin IAM user

python tests/e2e/preflight.py                   # read-only; fix what it reports
pytest -m e2e tests/e2e/test_1_seal.py          # ~25–50 min
pytest -m e2e tests/e2e/test_2_bringup.py       # ~40–75 min
pytest -m e2e tests/e2e/test_3_apply.py         # ~5–15 min
python tests/e2e/unseal.py                      # ~25 min, mostly CloudFront
```

About two and a half hours end to end. The three stages run separately on
purpose: stages 2 and 3 assert against a live account rather than against stage
1's memory, so either can be re-run alone while iterating.

`ENCLAVIZE_E2E_RUN_ID=<id>` makes stage 1 attach to a run that already happened
instead of dispatching another, which is how to re-check assertions without
spending a whole cycle.

`ENCLAVIZE_E2E=1` is only a collection gate. The account under test must also be
in `ENCLAVIZE_TEST_ACCOUNTS`, and the credentials must be able to undo what a run
does: root, or an IAM user with no permissions boundary. A boundary-carrying
principal is refused, because the apply boundary denies `iam:*` on the enclave
identities and `signin:*` outright — it could seal an account and never unseal
it.

## The domain, and why the first cycle differs

`transfer: real` accepts a transfer you started by hand from the spare account;
`transfer: bypass` is for an account that already holds the domain. Run `real`
first, until that path is proven, then `bypass` for everything after.

The account-to-account transfer is an internal AWS handover, not a registrar
transfer, so there is no sixty-day lock and the path can be re-run whenever you
want. The only clock is three days for the receiving account to accept.

`unseal.py --send-domain-back <spare-account-id>` offers the domain back and
prints the password to accept it with. That half is all this account can do; the
accepting half happens on the spare account.

## After unsealing

**The account can never pass the event audit again.** Every call `unseal.py`
makes carries no request id enclavize recorded — precisely the pattern the audit
exists to catch. That is fine for this loop, which always
bypasses the audit anyway, but it means a run that proves the audit for real
needs a fresh account with no way back in at all — no second root key, no admin
IAM user — and gets exactly one attempt. An admin user is caught the same way a
rescue key is: the `iam:CreateUser` that minted it is a root event on no
allow-list.

`app.teardown` runs first, while the hosted zone still exists for it to tidy up.
It executes on your machine with credentials that bypass the permission boundary
— a wider grant than the same script gets inside the account — so `unseal.py`
prints it and its commit sha and asks before running it. Without `--yes`, nothing
runs unanswered.
