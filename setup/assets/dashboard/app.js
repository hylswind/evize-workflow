// Reads status.json from this same bucket. Nothing here talks to any other
// host: a sealed account cannot reach out, and a page with no third-party
// requests means nobody outside can see who is looking at it.
//
// status.json is written by the setup program during the bring-up and rewritten
// as the state changes, so this page reflects progress without being rebuilt.

const STATES = {
  starting: "bringing the account up",
  "apply-ready": "apply interface ready",
  complete: "enclaved",
};

const PROOF = {
  published: "proof published",
  pending: "proof pending",
  missing: "proof missing — the sealing run did not publish one",
};

function show(status) {
  const domain = document.getElementById("domain");
  const state = document.getElementById("state");
  const proof = document.getElementById("proof");

  domain.textContent = status.domain || location.hostname.replace(/^dashboard\./, "");
  state.textContent = STATES[status.state] || status.state || "unknown";
  proof.textContent = PROOF[status.proof] || "";
}

fetch("./status.json", { cache: "no-store" })
  .then((response) => (response.ok ? response.json() : Promise.reject(response.status)))
  .then(show)
  .catch(() => {
    // The bucket is serving but status.json is not there yet, which is itself
    // worth saying: the page being reachable already proves DNS, the
    // certificate and the CDN are working.
    show({ state: "starting" });
  });
