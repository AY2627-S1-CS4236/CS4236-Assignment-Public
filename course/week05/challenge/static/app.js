"use strict";

const byId = id => document.getElementById(id);
const elements = Object.fromEntries([
  "connection-dot", "connection-label", "game-id", "suite-name", "wins",
  "wins-required", "progress-fill", "status-message", "reset-button",
  "target-hash1", "target-hash2", "hash-message", "hash-count", "hash-button",
  "hash-result", "hash-output", "hash-server-status", "left-message",
  "left-count", "right-message", "right-count", "collision-button",
  "result-indicator", "collision-result", "left-output", "right-output",
  "collision-server-status", "victory", "secret-output",
].map(id => [id, byId(id)]));

const state = {
  gameId: null,
  selected: "hash1",
  busy: false,
  hashes: {},
};

async function fetchJson(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed with status ${response.status}.`);
  return payload;
}

function jsonPost(body) {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

function parsedHex(value) {
  if (!/^[\t\n\v\f\r ]*(?:[0-9a-f]{2}[\t\n\v\f\r ]*)*$/i.test(value)) return null;
  return value.replace(/[\t\n\v\f\r ]/g, "").toLowerCase();
}

function setStatus(message, kind = "neutral") {
  elements["status-message"].textContent = message;
  elements["status-message"].dataset.kind = kind;
}

function selectedHash() {
  return state.hashes[state.selected];
}

function updateControls() {
  const values = {};
  for (const name of ["hash", "left", "right"]) {
    const hex = parsedHex(elements[`${name}-message`].value);
    values[name] = hex;
    elements[`${name}-count`].textContent = hex === null ? "—" : hex.length / 2;
  }
  const valid = hex => hex !== null && hex.length <= 8192;
  const target = selectedHash();
  const ready = Boolean(state.gameId) && Boolean(target) && !target.solved && !state.busy;
  elements["hash-button"].disabled = !ready || !valid(values.hash);
  elements["collision-button"].disabled = !ready || !valid(values.left)
    || !valid(values.right) || values.left === values.right;
  elements["reset-button"].disabled = !state.gameId || state.busy;
  for (const hashId of ["hash1", "hash2"]) {
    elements[`target-${hashId}`].disabled = !state.gameId || state.busy;
  }
}

function setBusy(busy) {
  state.busy = busy;
  updateControls();
}

function updateScore(wins, required) {
  elements.wins.textContent = wins;
  elements["wins-required"].textContent = required;
  elements["progress-fill"].style.width = `${Math.min(100, 100 * wins / required)}%`;
}

function renderDigest(target, hex) {
  target.replaceChildren();
  for (let offset = 0; offset < hex.length; offset += 32) {
    const block = document.createElement("code");
    block.textContent = hex.slice(offset, offset + 32);
    block.setAttribute("aria-label", `digest block ${offset / 32 + 1}`);
    target.append(block);
  }
}

function renderSelectedTarget(resetResults = true) {
  const target = selectedHash();
  if (!target) return;
  for (const hashId of ["hash1", "hash2"]) {
    const card = elements[`target-${hashId}`];
    const hash = state.hashes[hashId];
    card.classList.toggle("selected", hashId === state.selected);
    card.classList.toggle("solved", Boolean(hash?.solved));
    card.setAttribute("aria-pressed", String(hashId === state.selected));
    card.querySelector('[data-role="target-status"]').textContent = hash?.solved ? "Solved" : "Available";
    if (hash) {
      card.querySelector('[data-role="capacity"]').textContent = hash.capacity_bytes;
      card.querySelector('[data-role="rate"]').textContent = hash.rate_bytes;
      card.querySelector('[data-role="digest"]').textContent = hash.digest_bytes;
    }
  }
  document.querySelectorAll("[data-selected-name]").forEach(node => {
    node.textContent = target.hash_id === "hash1" ? "Hash 1" : "Hash 2";
  });
  document.querySelectorAll("[data-selected-formula]").forEach(node => {
    node.textContent = `c=${target.capacity_bytes} · rate=${target.rate_bytes} · digest=${target.digest_bytes}`;
  });
  if (resetResults) {
    elements["hash-result"].hidden = true;
    elements["collision-result"].hidden = true;
    elements["result-indicator"].textContent = target.solved ? "Target solved" : "Awaiting a collision";
    elements["result-indicator"].dataset.result = target.solved ? "valid" : "neutral";
    elements["hash-server-status"].textContent = target.solved
      ? "This target is locked until reset. Select the remaining target."
      : "Waiting for a hash query.";
    elements["collision-server-status"].textContent = target.solved
      ? "This target has already been solved."
      : "A valid collision solves this target.";
  }
  updateControls();
}

function clearVictory() {
  elements["secret-output"].textContent = "";
  elements.victory.hidden = true;
}

function applyGame(game, clearSecret = true) {
  state.gameId = game.game_id;
  state.hashes = Object.fromEntries(game.hashes.map(hash => [hash.hash_id, hash]));
  state.selected = game.hashes.find(hash => !hash.solved)?.hash_id || "hash1";
  elements["game-id"].textContent = game.game_id;
  elements["suite-name"].textContent = game.suite.name;
  updateScore(game.wins, game.wins_required);
  if (clearSecret) clearVictory();
  renderSelectedTarget();
}

async function openGame() {
  setBusy(true);
  try {
    const health = await fetchJson("/health");
    elements["connection-dot"].classList.toggle("online", health.status === "ok");
    const game = await fetchJson("/api/v1/games", { method: "POST" });
    applyGame(game);
    elements["connection-label"].textContent = "Server online";
    setStatus("Game ready. Choose either hash target.", "success");
  } catch (error) {
    elements["connection-dot"].classList.remove("online");
    elements["connection-label"].textContent = "Server unavailable";
    setStatus(`${error.message} Use Reset game to retry.`, "error");
  } finally {
    setBusy(false);
  }
}

async function resetGame() {
  if (!state.gameId) return openGame();
  setBusy(true);
  setStatus("Clearing progress and starting a fresh game…");
  try {
    applyGame(await fetchJson(`/api/v1/games/${encodeURIComponent(state.gameId)}/reset`, { method: "POST" }));
    setStatus("Game reset. Both hash targets are available.", "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function hashMessage() {
  setBusy(true);
  setStatus(`The Server is evaluating ${state.selected}…`);
  try {
    const result = await fetchJson(`/api/v1/games/${encodeURIComponent(state.gameId)}/hash`, jsonPost({
      hash_id: state.selected,
      message_hex: parsedHex(elements["hash-message"].value),
    }));
    renderDigest(elements["hash-output"], result.digest_hex);
    elements["hash-result"].hidden = false;
    elements["hash-server-status"].textContent = `Returned ${result.digest_hex.length / 2} digest bytes.`;
    setStatus("Hash returned. You may query again or submit a collision.", "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function submitCollision() {
  const submittedHashId = state.selected;
  setBusy(true);
  setStatus(`The Server is checking the ${submittedHashId} collision…`);
  try {
    const result = await fetchJson(`/api/v1/games/${encodeURIComponent(state.gameId)}/collide`, jsonPost({
      hash_id: submittedHashId,
      left_hex: parsedHex(elements["left-message"].value),
      right_hex: parsedHex(elements["right-message"].value),
    }));
    updateScore(result.wins, result.wins_required);
    renderDigest(elements["left-output"], result.left_digest_hex);
    renderDigest(elements["right-output"], result.right_digest_hex);
    elements["collision-result"].hidden = false;
    elements["result-indicator"].dataset.result = result.valid ? "valid" : "invalid";
    if (result.valid) {
      state.hashes[submittedHashId].solved = true;
      elements["result-indicator"].textContent = "Valid collision · target solved";
      elements["collision-server-status"].textContent = "The Server accepted this collision.";
      renderSelectedTarget(false);
      if (!result.complete) {
        state.selected = Object.values(state.hashes).find(hash => !hash.solved).hash_id;
        renderSelectedTarget();
        setStatus("First target solved. The remaining target is selected.", "success");
      } else {
        elements["secret-output"].textContent = result.secret;
        elements.victory.hidden = false;
        setStatus("Both targets solved. The Server revealed its startup secret.", "success");
      }
    } else {
      elements["result-indicator"].textContent = result.distinct ? "The complete digests differ" : "The decoded messages are identical";
      elements["collision-server-status"].textContent = "Try another pair. Existing progress is unchanged.";
      setStatus("Collision rejected. Existing progress is unchanged.", "error");
    }
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

for (const name of ["hash", "left", "right"]) elements[`${name}-message`].addEventListener("input", updateControls);
for (const hashId of ["hash1", "hash2"]) {
  elements[`target-${hashId}`].addEventListener("click", () => {
    state.selected = hashId;
    renderSelectedTarget();
    setStatus(`${hashId === "hash1" ? "Hash 1" : "Hash 2"} selected.`);
  });
}
elements["hash-button"].addEventListener("click", hashMessage);
elements["collision-button"].addEventListener("click", submitCollision);
elements["reset-button"].addEventListener("click", resetGame);
updateControls();
openGame();
