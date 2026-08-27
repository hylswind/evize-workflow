# enclavize

Drives an AWS account out of human control, and signs a statement saying so.

An enclave proves what is running inside it and that nothing outside can
interfere. This does the same thing for an AWS account: it removes every
credential a person holds, closes the console, kills the address that could
reset the password, hands the account to one pinned program, and then audits its
own work and signs the verdict.

The trust anchor is the code itself. This workflow runs in the open at a commit
the caller pinned, and the signature on the statement names that exact workflow
rather than the repository that called it — so one verifier covers every account
sealed this way, and anyone can read what sealed it.

---

# Using it

A run has two halves: a GitHub workflow seals the account, and the account then
builds the rest of itself. The steps below are the whole sequence in order.

## 1. A caller repository

enclavize is a reusable workflow. You call it from a repository of your own,
which is where your secrets live and which is what the attestation is issued to.

```yaml
# .github/workflows/<caller-workflow>.yml — the name is yours to choose
on:
  workflow_dispatch:
    inputs:
      domain:
        description: the domain being transferred in
        required: true
        type: string
      start:
        description: window start, unix seconds, must be in the past
        required: true
        type: string
      repo:
        description: the application repo whose commits this account can apply (owner/name)
        required: true
        type: string
      bypass_event_check:
        description: skip the history audit (marks the statement debug)
        type: boolean
        default: false
      bypass_domain_transfer:
        description: skip accepting the transfer (marks the statement debug)
        type: boolean
        default: false

jobs:
  enclavize:
    permissions:
      id-token: write
      attestations: write
      contents: read
    uses: <owner>/enclavize-workflow/.github/workflows/enclavize.yml@<commit-sha>
    with:
      domain: ${{ inputs.domain }}
      start: ${{ inputs.start }}
      repo: ${{ inputs.repo }}
      bypass_event_check: ${{ inputs.bypass_event_check }}
      bypass_domain_transfer: ${{ inputs.bypass_domain_transfer }}
    secrets:
      ROOT_KEY_ID: ${{ secrets.ROOT_KEY_ID }}
      ROOT_SECRET: ${{ secrets.ROOT_SECRET }}
      TRANSFER_PASSWORD: ${{ secrets.TRANSFER_PASSWORD }}
      APPLY_API_KEY: ${{ secrets.APPLY_API_KEY }}
      CONSOLE_ZIP_PASSWORD: ${{ secrets.CONSOLE_ZIP_PASSWORD }}
```

Declaring the inputs and forwarding them, rather than writing the values into
`with:`, is what lets one caller seal an account without being edited each time —
and it is the shape the end-to-end suite drives, so it is the one actually
exercised.

Two things are not optional:

**Pin to a commit sha, not a tag or a branch.** The sha is what a verifier
anchors to, and it is also the commit the account's own setup program is cloned
from — so a moving ref means the proof names something that can change afterwards.

**Grant all three permissions.** A reusable workflow receives the intersection of
its own permissions and the caller's, so omitting one silently produces a run
with no signature.

## 2. Before you run

The account's identity rests on an email address at a domain that the account
itself will end up owning — and once it owns it, the setup program publishes a
null MX so that address stops working. Nobody can ever receive a password reset.
That is why the domain comes first.

1. On a **spare** AWS account, register the domain.
2. Point its MX at a mailbox you can read.
3. Sign up a **new** AWS account using an address at that domain. This is the
   account that gets enclavized.
4. In the new account's console, allow IAM users to access billing.
5. In the same console, open **AWS Organizations** and create an organization.
   The account becomes its own management account; add no member accounts.
6. Create a root access key for it.
7. Back on the spare account, start a domain transfer to the new account's id,
   and keep the transfer password it gives you.

The transfer is an AWS account-to-account handover, not a registrar transfer:
there is no sixty-day lock, and the receiving side has three days to accept.

**Step 5 is what makes step 3 checkable.** An account cannot read its own root
email address: `account:GetPrimaryEmail` refuses a standalone account whether it
asks as root or as an administrator, and CloudTrail redacts the address out of
the sign-up event. `DescribeOrganization` takes no arguments, so there is no own
account id for it to refuse — it simply names the management account and its
email. With the organization in place, the run reads that address and stops if it
is not at `domain`. Without it, the run stops too, and says to do this.

## 3. The five secrets

All five are required. Set them on the caller repository.

| secret | what it is |
|---|---|
| `ROOT_KEY_ID` | the root access key from step 6. **The run deletes it** |
| `ROOT_SECRET` | its secret |
| `TRANSFER_PASSWORD` | from step 7, to accept the domain transfer |
| `APPLY_API_KEY` | a value **you choose**, which becomes the key for the apply endpoint |
| `CONSOLE_ZIP_PASSWORD` | encrypts the console credentials before they become an artifact |

`APPLY_API_KEY` is yours to pick because a sealed account cannot hand one back:
an API-Gateway-generated key would be readable only from inside an account that
by then has no console and no credentials. Choose it now and keep it.

## 4. The inputs

| input | meaning |
|---|---|
| `domain` | the domain being transferred in, bare: `example.com` |
| `start` | unix seconds: `1700000000`. The audit window opens here, and must be in the past |
| `repo` | the application repo whose commits this account can apply, as `owner/name`: `acme/my-application` |
| `bypass_event_check` | skip the history audit. Marks the statement `debug` |
| `bypass_domain_transfer` | skip accepting the transfer, for an account that already holds the domain. Marks the statement `debug` |

Both bypasses exist for reusing an account while developing. **A production run
uses neither.**

## 5. Run it

```sh
CALLER=<owner>/<caller-repo>
WORKFLOW=<caller-workflow>.yml

gh workflow run "$WORKFLOW" --repo "$CALLER" \
  -f domain=example.com \
  -f start=1700000000 \
  -f repo=acme/my-application
  # while developing, add either or both — each marks the statement debug:
  #   -f bypass_event_check=true
  #   -f bypass_domain_transfer=true

gh run list --repo "$CALLER" --workflow "$WORKFLOW" --limit 1  # gh does not return the id it started
gh run watch <run-id> --repo "$CALLER"
```

It leaves two artifacts:

```sh
gh run download <run-id> --repo "$CALLER" -n enclavize-statement
gh run download <run-id> --repo "$CALLER" -n enclavize-console
```

### `statement.json` — what was sealed

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

`bypasses` records the two inputs as they were given, and `debug` is computed
from them: true if either was used. Nothing sets `debug` separately, so it
cannot claim a clean run that the bypasses beside it contradict.

**Only a statement with `debug: false` means a fully sealed account.** A
`debug: true` statement is a rehearsal, signed under the same identity on
purpose — the flag is the distinction, not the signer.

The account publishes this same file at `https://proof.{domain}/`, alongside the
Sigstore bundle it was signed with — so it can be verified from what the account
itself serves, without asking GitHub anything.

### `console.json` — how to sign in

It arrives inside `console.7z`, encrypted with the password you set:

```sh
7z x -p"$CONSOLE_ZIP_PASSWORD" console.7z
```

```json
{
  "signInUrl": "https://123456789012.signin.aws.amazon.com/console",
  "userName": "enclavize-console",
  "password": "…"
}
```

Step 6 is where you use it.

## 6. Watch CloudFront until the account is ready

By the time the workflow ends, the account is already sealed and an instance
inside it is building the rest. The console user is how you watch that happen —
it is the only human access that survives.

1. Sign in with the three fields from `console.json`. The user can change its
   own password.
2. Go to **CloudFront → Distributions**.
3. Wait until **both** distributions read **Deployed**.

**Do not open the dashboard while you wait.** Ask too early and you get "no such
host" — and your resolver caches that answer. It keeps giving you the same error
after the name is working, until the TTL runs out.

## 7. The dashboard

Once both distributions are Deployed, open `https://dashboard.{domain}`.

It shows where the bring-up got to, **which repo this domain is bound to**, and
every commit that has been applied, newest first. Older months load on demand,
so however long the account runs, all of its history stays reachable.

## 8. Applying a commit

An apply runs one commit's `setup.sh` inside the account. What that script does
is its own business: ship a new version of the application, rearrange the
account's resources, or both.

### What the application repo must look like

**One thing: an executable `setup.sh` at the repository root.** That is the
whole interface. An instance clones the repo at the commit you name, checks it
out, and runs that script as root with `ENCLAVIZE_DOMAIN` set — the domain this
account holds, and where the application builds its own names.

It runs with `AdministratorAccess`, capped by a permission boundary — so it can
build whatever the application needs and still cannot touch the enclave.

### If it creates a role or a user

The boundary must go on it. `iam:CreateRole` and `iam:CreateUser` are **denied**
unless the new principal carries the boundary, so this is not advice — the call
fails without it:

```python
import json
import boto3

iam = boto3.client("iam")
account = boto3.client("sts").get_caller_identity()["Account"]
BOUNDARY = f"arn:aws:iam::{account}:policy/enclavize-apply-boundary"

trust = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole",
}]}

iam.create_role(
    RoleName="my-worker",
    AssumeRolePolicyDocument=json.dumps(trust),
    PermissionsBoundary=BOUNDARY,   # omit this and the call is denied
)

iam.create_user(UserName="my-worker", PermissionsBoundary=BOUNDARY)
```

The boundary carries that rule itself, so it propagates: anything your role
creates must carry it too. The fence holds at any depth rather than ending at
the first role an applied commit makes for itself.

### Applying it

```
curl -X POST https://apply.{domain}/v1/commits \
  -H "x-api-key: $APPLY_API_KEY" \
  -H 'content-type: application/json' \
  -d '{"commit":"<40-hex sha>"}'
```

```json
{"commit": "b5cdb1ce…", "instanceId": "i-0abc…", "status": "launched"}
```

`launched`, not `applied`: the instance has only just started. It answers
immediately rather than waiting, because both the Express workflow behind it and
API Gateway's integration time out well before a real `setup.sh` could finish.

The commit must be a full 40-hex sha — not a tag, not a short one. Anything else
is refused with **400**, and a wrong key with **403**; neither starts anything.

---

# How it works

## What the sealing run does

The order is the security property. Everything reversible happens first.

1. Resolve the application repo's numeric id.
2. **Check the root email is at this domain**, by reading the organization's
   management account. The null MX kills a mailbox only if the mailbox is there;
   an account signed up elsewhere would seal into something that merely looks
   sealed.
3. Create the identities that outlive root: an admin role only EC2 can assume,
   an event reader, a starter, and a console user that can see billing and the
   *shape* of the account — which resources exist — but not what is inside them.
   It can list a bucket and not open an object, and cannot read a secret, a
   parameter or a database item.
4. Accept the domain transfer.
5. **Close the console.** An empty VPC is created solely to be named as the only
   permitted source of sign-in traffic; nothing can originate from it.
6. **Launch the setup instance.** It blocks in its user-data until the go flag,
   so nothing it does can precede the seal. This is the last thing root is
   needed for.
7. **Delete the root key.** No human credential remains.
8. Hold, so history settles and the lockout replicates. A run that bypasses the
   audit holds for nothing instead — the wait is for the history's sake — and
   its statement records the hold it actually took.
9. Audit. **Only what root did** — root is the one credential a person was ever
   handed, and any escalation from it leaves a root-produced trace at its root.
   The history is judged in two halves: before the run began, a short allow-list
   covers exactly the manual preparation above — signing up, creating the
   organization, minting the root key; from the run's first call onward, every
   root event must carry a request id enclavize itself recorded, which catches
   an extra call even when it looks exactly like one enclavize makes. The
   history must open with the account's own first events,
   and root must do nothing after deleting its key.
10. Fire the go flag. The account starts running itself.
11. Write the statement; the workflow signs it and publishes it into the account.

## What the account then builds itself

The setup program runs on the instance, under the admin role, cloned from this
repo at the same commit the workflow was pinned to — so it is covered by the same
attestation. It builds:

- a hosted zone, since a transferred domain does not bring its old one, and
  points the registrar at it
- a null MX (RFC 7505), which kills the account's email address
- a certificate covering all three public names
- `dashboard.{domain}`, served from `setup/assets/dashboard/` — static files,
  nothing to build
- `proof.{domain}`, serving the signed statement and its bundle
- `apply.{domain}`, the interface above

It then checks the published statement against its bundle, deletes the starter
user — after which nothing inside the account can rewrite the proof — and
terminates itself, so nothing is left holding admin.

Nearly all of it happens at once. The certificate is the wait — ACM validates
through DNS on its own schedule, and nothing can hurry it — after which both
distributions are created together and deploy in parallel rather than in turn.

### Where the boundary stops an applied commit

An apply instance can build whatever the application needs — its own API Gateway
APIs, Step Functions workflows, CloudFront distributions, and records anywhere in
the domain including the apex.

What it cannot touch is the enclave itself: the `enclavize-*` identities, the
sign-in lock, the domain registration, the proof and dashboard buckets,
enclavize's own API, custom domain, state machine and two distributions, the
`dashboard.`, `proof.` and `apply.` records, and the apex MX, NS and SOA.

That last set matters as much as the rest: taking `apply.{domain}` would let an
application answer in the enclave's place and read the API key out of the header
of every request meant for the real endpoint.

### The dashboard

The page fetches nothing from another host: no fonts, no scripts, no analytics.
That is not tidiness. Nobody outside can see who is reading it, and nobody
outside can restyle a page whose whole purpose is to be believed.

Its apply log is something the account has to keep for itself, because a static
page cannot list a bucket and nothing in a sealed account runs on a schedule.
Every apply is what rebuilds it: the state machine writes a record, then derives
the index from a listing — one shard per month, plus a manifest naming the
months. Deriving rather than appending is what makes it self-healing; a shard
written badly is replaced wholesale by the next apply in that month.

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
and takes it apart again. It is not tied to any particular caller or
application: which reusable workflow signs is read from the caller's own
workflow file, and everything else comes from a profile.

```
ENCLAVIZE_E2E=1 ENCLAVIZE_E2E_PROFILE=tests/e2e/profiles/mine.yml \
ENCLAVIZE_TEST_ACCOUNTS=111122223333 \
  python tests/e2e/preflight.py && pytest -m e2e tests/e2e/
```

`tests/e2e/README.md` has the cycle, and what a caller and an application each
have to look like to be testable. Two parts of it need no account at all and run
in an ordinary `pytest`: `test_profile.py` covers the profile schema and the
derivation of the signer workflow from a caller, and `test_teardown.py` covers
the order the teardown removes things in.

## Debugging a run

**Everything here needs a credential that survived the seal** — a second root
key, or an admin IAM user created before the run. You have one only if you made
one beforehand on purpose. Do that while developing; never for a real run, where
being able to get back in is exactly what must not be true.

Keeping one also means the account can never pass the audit. A second root key
is a second `CreateAccessKey` where the check permits one, an admin user is an
`iam:CreateUser` on no allow-list, and every call you then make is a root event
carrying no request id enclavize recorded.

With such a credential the console lock is no obstacle: sign-in policies gate
interactive sign-in and never a signed API call, so it can always be undone.

```
aws signin delete-console-authorization-configuration --target-id <account> --region us-east-1
aws signin list-resource-permission-statements --region us-east-1
aws signin delete-resource-permission-statement --statement-id <id> --region us-east-1
```

To take a whole run apart — a seal its audit refused, a bring-up that died
halfway, an account you want back:

```
python scripts/cleanup.py
```

It needs nothing but those credentials. The domain is read from the account, and
it names the account and makes you type the id back before removing anything. It
removes what enclavize built and lists what it did not: an application's own
resources are its own teardown's business.

Without such a credential none of this is available, and the account cannot be
recovered. Run the workflow again on a fresh one.
