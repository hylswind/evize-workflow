// Everything this page reads comes from its own bucket. The only other host it
// names is github.com, and only as the target of a link a person may click —
// nothing is fetched from there, so no outside host learns who is looking.
// Those links open in a new tab and carry rel="noreferrer", which both keeps
// this page where it was and denies the opened tab a handle back to it.
//
// Four kinds of file, all written by the account itself:
//
//   status.json                  domain, bound repo, where the bring-up got to
//   applies.json                 which months hold applies, by shard key
//   applies/index/{YYYY-MM}.json one month's applies, by record key
//   applies/{at}_{commit}.json   one apply: what became of it
//
// The month shards are what keep the whole history reachable without ever
// fetching all of it: the newest opens on load, and each "earlier" walks back
// one more. The records are small and fetched one by one for the month on
// show, because a listing says only that an apply happened — the record says
// whether it is serving, preparing, or gone.

const STATES = {
  starting: "setting up",
  "apply-ready": "apply ready",
  complete: "completed",
};

// What a record's status means to a person. Anything else is shown as it is.
const OUTCOMES = {
  launched: "serving",
  preparing: "preparing",
  retired: "retired",
  failed: "failed",
};

const RECORDS = "applies/";
const SHARDS = "applies/index/";
const SUFFIX = ".json";

const el = (id) => document.getElementById(id);

function read(path) {
  return fetch(path, { cache: "no-store" }).then((response) =>
    response.ok ? response.json() : Promise.reject(new Error(String(response.status)))
  );
}

// applies/2026-08-26T19:49:26.300Z_b5cdb1ce…c15.json
// The timestamp leads so the keys sort in the order things happened, and the
// underscore is the one separator an ISO timestamp does not already contain.
function parseRecord(key) {
  const bare = key.slice(RECORDS.length, -SUFFIX.length);
  const cut = bare.indexOf("_");
  return cut < 0 ? null : { key, at: bare.slice(0, cut), commit: bare.slice(cut + 1) };
}

function parseMonth(key) {
  return key.slice(SHARDS.length, -SUFFIX.length);
}

function stamp(at) {
  return at.replace("T", " ").replace(/\.\d+Z$/, "Z");
}

const view = { repo: null, months: [], opened: 0, rows: 0 };

function note(text, tone) {
  const p = el("note");
  p.textContent = text || "";
  p.hidden = !text;
  if (tone) {
    p.dataset.tone = tone;
  } else {
    delete p.dataset.tone;
  }
}

function commitLink(sha, className) {
  // A link only when the repo is known — a commit with nowhere to point should
  // not look like something to click.
  //
  // The tree at that commit, not the commit itself: an apply runs the whole
  // repository as it stood, so the tree is what was applied. A diff only says
  // what changed since whatever came before it, which may never have run here.
  const commit = document.createElement(view.repo ? "a" : "span");
  commit.className = className;
  commit.textContent = sha.slice(0, 12);
  if (view.repo) {
    commit.href = `https://github.com/${view.repo}/tree/${sha}`;
    commit.target = "_blank";
    commit.rel = "noreferrer";
    commit.title = sha;
  }
  return commit;
}

function row(record, position) {
  const li = document.createElement("li");
  // Capped: a month of two hundred applies should not take six seconds to
  // finish arriving.
  li.style.animationDelay = `${Math.min(position, 12) * 30}ms`;

  const at = document.createElement("span");
  at.className = "at";
  at.textContent = stamp(record.at);

  const outcome = document.createElement("span");
  outcome.className = "outcome";
  outcome.dataset.outcome = record.status || "unknown";
  outcome.textContent = OUTCOMES[record.status] || record.status || "—";

  li.append(at, commitLink(record.commit, "commit"), outcome);
  return li;
}

function showStatus(status) {
  const state = el("state");
  const key = status.state;
  state.dataset.state = key || "unknown";
  state.textContent = STATES[key] || key || "unknown";

  // The page is uploaded verbatim, so the domain cannot be baked into it.
  el("domain").textContent =
    status.domain || location.hostname.replace(/^dashboard\./, "");

  const repo = el("repo");
  if (status.appRepo) {
    view.repo = status.appRepo;
    repo.textContent = status.appRepo;
    repo.href = `https://github.com/${status.appRepo}`;
    repo.target = "_blank";
    repo.rel = "noreferrer";
    repo.classList.remove("pending");
  } else {
    // An account brought up before the field existed, rather than an error.
    repo.textContent = "not recorded";
  }
}

// What is serving and what is coming, read off the newest month's records: the
// one marked launched, and any still preparing. The same records the log
// shows, so the two cannot disagree.
function showVersions(records) {
  const serving = records.find((r) => r.status === "launched");
  const next = records.find((r) => r.status === "preparing");

  const servingEl = el("serving");
  servingEl.textContent = "";
  if (serving) {
    servingEl.append(commitLink(serving.commit, "commit"),
      document.createTextNode(` since ${stamp(serving.since || serving.startedAt || serving.at)}`));
  } else {
    servingEl.textContent = "nothing yet";
  }

  const nextEl = el("next");
  nextEl.textContent = "";
  if (next) {
    nextEl.append(commitLink(next.commit, "commit"),
      document.createTextNode(` preparing since ${stamp(next.startedAt || next.at)}`));
  } else {
    nextEl.textContent = "—";
  }
}

function showEarlier() {
  const button = el("earlier");
  const next = view.months[view.opened];
  button.hidden = !next;
  if (next) {
    button.textContent = `earlier · ${next.month}`;
    button.disabled = false;
  }
}

// Each record, so the row can say what became of the apply. A record that
// cannot be read still gets its row: the listing proved the apply happened.
function withOutcomes(records) {
  return Promise.all(records.map((record) =>
    read(`./${record.key}`).then(
      (body) => Object.assign({}, record, body),
      () => record
    )
  ));
}

function openNextMonth() {
  const month = view.months[view.opened];
  if (!month) {
    return Promise.resolve();
  }
  el("earlier").disabled = true;

  return read(`./${month.key}`).then(
    (shard) => {
      const listed = (shard.applies || [])
        .map(parseRecord)
        .filter(Boolean)
        .sort((a, b) => (a.at < b.at ? 1 : -1));
      return withOutcomes(listed).then((records) => {
        const first = view.opened === 0;
        view.opened += 1;
        if (first) {
          showVersions(records);
        }

        const list = el("applies");
        records.forEach((record) => list.append(row(record, view.rows++)));
        el("count").textContent = String(view.rows).padStart(3, "0");

        if (shard.truncated) {
          note(`${month.month} holds more applies than one listing returns; the oldest of that month are not shown.`, "lost");
        } else if (!view.rows) {
          note("nothing applied yet.");
        } else {
          note("");
        }
        showEarlier();
      });
    },
    () => {
      note(`${month.month} could not be read.`, "lost");
      el("earlier").disabled = false;
    }
  );
}

function showLog(manifest) {
  view.months = (manifest.months || [])
    .map((key) => ({ key, month: parseMonth(key) }))
    // Newest first: the month a person wants is the one that just happened.
    .sort((a, b) => (a.month < b.month ? 1 : -1));

  if (!view.months.length) {
    el("count").textContent = "000";
    showVersions([]);
    note("nothing applied yet.");
    return Promise.resolve();
  }
  return openNextMonth();
}

// The status comes first and the log second, rather than both at once: the log
// needs the bound repo to know where a commit points, and a row built before
// that arrived would be plain text where every other row is a link.
read("./status.json")
  .then(showStatus, () =>
    // The bucket answers but status.json is not there yet, which is itself
    // worth saying: the page being reachable already proves DNS, the
    // certificate and the CDN are working.
    showStatus({ state: "starting" })
  )
  .then(() =>
    read("./applies.json").then(showLog, () => {
      el("count").textContent = "000";
      showVersions([]);
      note("nothing applied yet.");
    })
  );

el("earlier").addEventListener("click", openNextMonth);
