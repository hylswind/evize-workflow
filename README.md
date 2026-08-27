# enclavize

Drives an AWS account out of human control, and signs a statement saying so.

An enclave proves what is running inside it and that nothing outside can
interfere. This does the same thing for an AWS account: it removes every
credential a person holds, closes the console, kills the address that could
reset the password, hands the account to one pinned program, and then audits its
own work and signs the verdict.

The trust anchor is the code itself. This workflow runs in the open at a commit
the caller pinned, and the signature on the statement names that exact workflow —
so anyone can read what sealed the account, and verify that nothing else did.

## Verifying an account

```
gh attestation verify statement.json \
  --repo <caller-owner>/<caller-repo> \
  --signer-workflow <owner>/enclavize-workflow/.github/workflows/enclavize.yml \
  --predicate-type https://enclavize.dev/enclaved-account/v1
```

`--signer-workflow` is what matters: the attestation is signed by this reusable
workflow rather than by whatever repo called it, so one verifier covers every
account enclavized this way.

The statement:

```json
{
  "accountID": "123456789012",
  "domain": "example.com",
  "start": 1700000000,
  "holdSeconds": 900,
  "repoID": 1318129369,
  "debug": false,
  "bypasses": { "eventCheck": false, "domainTransfer": false }
}
```

`debug` is true when any check was skipped, and `bypasses` says which. **Only a
statement with `debug: false` means a fully sealed account.** A `debug: true`
statement is a rehearsal, signed under the same identity on purpose — the flag
is the distinction, not the signer.

## Using it

```yaml
jobs:
  enclavize:
    permissions:
      id-token: write
      attestations: write
      contents: read
    uses: <owner>/enclavize-workflow/.github/workflows/enclavize.yml@<commit-sha>
    with:
      domain: example.com
      start: "1700000000"
      repo: acme/my-application
    secrets:
      ROOT_KEY_ID: ${{ secrets.ROOT_KEY_ID }}
      ROOT_SECRET: ${{ secrets.ROOT_SECRET }}
      TRANSFER_PASSWORD: ${{ secrets.TRANSFER_PASSWORD }}
      APPLY_API_KEY: ${{ secrets.APPLY_API_KEY }}
      CONSOLE_ZIP_PASSWORD: ${{ secrets.CONSOLE_ZIP_PASSWORD }}
```

Pin to a commit sha, not a tag: the sha is what the verifier's `--signer-workflow`
check is anchored to, and it is also the commit the account's own setup program
is cloned from.

A caller must grant those three permissions. A reusable workflow gets the
intersection of its own and the caller's, so leaving them out means no signature.

### Before you run it

1. On a spare AWS account, register the domain (`example.com`).
2. Point its MX at a mailbox you can read.
3. Sign up a **new** AWS account using an address at that domain. This is the
   account that gets enclavized.
4. In its console, allow IAM users to access billing.
5. Create a root access key.
6. On the spare account, start a domain transfer to the new account's id, and
   keep the transfer password.

Steps 1–3 are the reason the domain matters: the account's identity rests on an
address at a domain the account itself will end up owning, and the setup program
then publishes a null MX so that address stops working.

### Inputs

| input | meaning |
|---|---|
| `domain` | the domain being transferred in |
| `start` | unix seconds; the audit window opens here and must be in the past |
| `repo` | the application repo whose commits this account can apply |
| `bypass_event_check` | skip the history audit. Marks the statement `debug` |
| `bypass_domain_transfer` | skip accepting the transfer, for an account that already holds the domain. Marks the statement `debug` |

Both bypasses exist for reusing an account while developing. A production run
uses neither.

## What a run does

Everything reversible happens first, so a wrong password or an unreachable
GitHub fails while the account can still be used normally.

1. Resolve the application repo's numeric id.
2. Create the identities that outlive root: an admin role only EC2 can assume,
   an event reader, a starter, and a console user that can see billing and the
   shape of the account — which resources exist — but not the data in them.
3. Accept the domain transfer.
4. **Close the console.** An empty VPC is created solely to be named as the only
   permitted source of sign-in traffic; nothing can originate from it.
5. **Launch the setup instance.** It blocks in its user-data until the go flag,
   so nothing it does can precede the seal. This is the last thing root is
   needed for.
6. **Delete the root key.** No human credential remains.
7. Hold, so history settles and the lockout replicates. A run that bypasses the
   audit holds for nothing instead — the wait is for the history's sake — and
   its statement records the hold it actually took.
8. Audit. **Only what root did** — root is the one credential a person was ever
   handed, and any escalation from it leaves a root-produced trace at its root.
   The history is judged in two halves: before the run began, a short allow-list
   covers signing up and minting the root key; from the run's first call onward,
   every root event must carry a request id enclavize itself recorded. The
   history must open with the account's own first events, and root must do
   nothing after deleting its key.
9. Fire the go flag. The account starts running itself.
10. Write the statement; the workflow signs it and publishes it into the account.

## What the account then builds itself

The setup program runs on the instance, under the admin role, and is cloned from
this repo at the same commit the workflow was pinned to — so it is covered by the
same attestation. It builds:

- a hosted zone, since a transferred domain does not bring its old one, and the
  registrar pointed at it
- a null MX (RFC 7505), which kills the account's email address
- a certificate covering all three public names
- `dashboard.{domain}`, served from `setup/assets/dashboard/` — static files,
  nothing to build
- `proof.{domain}`, serving the signed statement and the bundle it was signed
  with
- `apply.{domain}`, the interface described below

It then checks the published statement against its bundle, deletes the starter
user — after which nothing inside the account can rewrite the proof — and
terminates itself, so nothing is left holding admin.

### Knowing when it is ready

Watch the account's two CloudFront distributions until both read **Deployed**,
then open `https://dashboard.{domain}`. The page reports where the bring-up has
got to, which repo the domain is bound to, and every commit applied since —
`status.json` beside it carries the first two in machine-readable form.

The apply log is the part the account has to keep for itself. A static page
cannot list a bucket, so each apply leaves a record and rebuilds the index the
page reads: one shard per month, and a manifest naming the months. The page
opens the newest month and walks back from there, so however long the account
runs, all of it stays reachable and none of it has to be loaded at once.

Wait for Deployed before opening it rather than refreshing while you wait. Until
the distribution exists there is no address to answer at, and a resolver that
asks early will remember that there wasn't one for a quarter of an hour after
there is.

### Applying a commit

```
curl -X POST https://apply.{domain}/v1/commits \
  -H "x-api-key: $APPLY_API_KEY" \
  -H 'content-type: application/json' \
  -d '{"commit":"<40-hex sha>"}'
```

Applying a commit, not deploying an application: what that commit's `setup.sh`
does is its own business. It may ship a new version of the application, or only
rearrange the account's resources, or both. The account is whatever the last
applied commit made it.

The endpoint is a name rather than the generated `execute-api` one because
nothing in a sealed account can tell you the generated one — it is computed on
an instance that then terminates itself, in an account with no console and no
credentials. `apply.{domain}` follows from the domain alone.

The commit must be a 40-hex sha — checked at the edge, because it ends up in a
shell command. The state machine launches an instance and answers immediately;
it does not wait for the commit to finish applying, which is what keeps it
inside API Gateway's integration limit. Watch the dashboard for progress.

The application repo must have an executable `setup.sh` at its root. That is the
only interface enclavize requires of it.

An apply instance runs with `AdministratorAccess`, capped by a permission
boundary. It can build whatever the application needs — its own API Gateway
APIs, Step Functions workflows, CloudFront distributions, and records anywhere
in the domain including the apex.

What it cannot touch is the enclave itself: the `enclavize-*` identities, the
sign-in lock, the domain registration, the proof and dashboard buckets,
enclavize's own API, custom domain, state machine and two distributions, the
`dashboard.`, `proof.` and `apply.` records, and the apex MX, NS and SOA.

That last set matters as much as the rest: taking `apply.{domain}` would let an
application answer in the enclave's place and read the API key out of the header
of every request meant for the real endpoint.

The boundary carries the rule that anything created under it must carry it too,
so the fence holds at any depth rather than ending at the first role an applied
commit makes for itself.

## Layout

The code is in three layers, and the split is what makes it testable:

```
enclavize/aws/     one module per service; the only place boto3 is called
enclavize/logic/   policy documents, the audit verdict, the statement, user-data
workflow/          phase A: ordering, credential choice, nothing else
setup/             phase B: the same, for the bring-up
```

A step never contains AWS usage of its own — it picks modules and orders them.
That is why real-account tests target `enclavize/aws/*` and steps are covered by
ordering tests alone.

## Tests

```
pytest                     # offline: moto and hand-written fakes. No AWS, no credentials.
```

Real-account tests are opt-in twice over: they are not collected without
`ENCLAVIZE_AWS_TEST=1`, and they refuse to run unless the account answering STS
is listed in `ENCLAVIZE_TEST_ACCOUNTS`.

```
ENCLAVIZE_AWS_TEST=1 ENCLAVIZE_TEST_ACCOUNTS=111122223333 \
  pytest -m aws tests/aws/test_iam.py
```

**These cover only what can clean up after itself** — `iam`, `ec2`, `s3`, `ssm`,
`events`, `dns`, `sfn`, `apigw`, `sts`. Every resource is named with a per-run
prefix and deleted by it, so they are safe to run against any scratch account
and safe to run twice. Anything a crashed run leaves behind is removed with:

```
python tests/aws/reaper.py --prefix t1a2b3c4-
```

Modules that cannot be exercised this way are left to the end-to-end run
instead: `signin` locks the account's console, `domains.accept_transfer` needs a
real pending transfer and moves the domain when it succeeds, `apigw`'s custom
domain needs a certificate for a domain the account actually holds, and `acm`
and `cdn` leave resources that take far longer to retire than to create. Those
are all proven by a full run against a sacrificial account rather than in
isolation.

`tests/aws/test_proof_handoff.py` drives both halves of the proof exchange in one
account. It is the only place the two phases interact, and the failure it guards
against — a bucket policy that locks out an upload still in flight — only appears
when they overlap.

`tests/aws/test_events.py` prints the `(eventSource, eventName)` pairs a real
account actually produces, which is how the audit whitelist gets tuned.

### End to end

`tests/e2e/` seals a real account, checks what it built, applies a commit to it,
and takes it apart again — about two and a half hours. It is not tied to any
particular caller or application: which reusable workflow signs is read from the
caller's own workflow file, and everything else comes from a profile.

```
ENCLAVIZE_E2E=1 ENCLAVIZE_E2E_PROFILE=tests/e2e/profiles/mine.yml \
ENCLAVIZE_TEST_ACCOUNTS=111122223333 \
  python tests/e2e/preflight.py && pytest -m e2e tests/e2e/
```

`tests/e2e/README.md` has the cycle, and what a caller and an application each
have to look like to be testable. One part of it needs no account at all and
runs in an ordinary `pytest`: `tests/e2e/test_profile.py` covers the profile
schema and the derivation of the signer workflow from a caller.

## Recovering

If a run dies with the console locked, sign-in policies never apply to API calls,
so any credential that reaches the API can undo it:

```
aws signin delete-console-authorization-configuration --target-id <account> --region us-east-1
aws signin list-resource-permission-statements --region us-east-1
aws signin delete-resource-permission-statement --statement-id <id> --region us-east-1
```

If the root key is already gone, the account cannot be recovered — that is the
point. Run the workflow again on a fresh account.
