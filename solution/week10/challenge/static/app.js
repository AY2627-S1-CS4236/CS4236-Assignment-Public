"use strict";

const element = (id) => document.getElementById(id);
const state = { game: null, busy: false };
const messageInputs = [element("oracle-message"), element("forge-message")];
const signatureInputs = [element("forge-r"), element("forge-s")];

element("oracle-message").value = "435334323336";
element("forge-message").value = "6672657368206d657373616765";

function normalizedHex(value) {
  // Match bytes.fromhex: whitespace may separate complete byte pairs.
  if (!/^(?:[ \t\n\r\v\f]*[0-9a-f]{2})*[ \t\n\r\v\f]*$/i.test(value)) return null;
  return value.replace(/[ \t\n\r\v\f]/g, "").toLowerCase();
}

function setStatus(message, kind = "neutral") {
  element("status-message").textContent = message;
  element("status-message").dataset.kind = kind;
}

function updateControls() {
  const oracle = normalizedHex(messageInputs[0].value);
  const forge = normalizedHex(messageInputs[1].value);
  element("oracle-count").textContent = oracle === null ? "—" : oracle.length / 2;
  element("forge-count").textContent = forge === null ? "—" : forge.length / 2;
  const ready = Boolean(state.game) && !state.game.complete && !state.busy;
  element("oracle-button").disabled = !ready || oracle === null || oracle.length > 8192;
  element("forge-button").disabled = !ready || forge === null || forge.length > 8192
    || signatureInputs.some((input) => !/^[0-9]+$/.test(input.value.trim()));
  element("reset-button").disabled = state.busy;
  element("reset-button").firstChild.textContent = state.game ? "Reset game " : "Reconnect ";
  [...messageInputs, ...signatureInputs].forEach((input) => { input.disabled = !ready; });
}

function setBusy(busy) {
  state.busy = busy;
  updateControls();
}

async function post(path, body) {
  const options = { method: "POST" };
  if (body !== undefined) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status}).`);
  return payload;
}

function gamePath(operation) {
  return `/api/v1/games/${encodeURIComponent(state.game.game_id)}/${operation}`;
}

function applyGame(game) {
  state.game = game;
  element("game-id").textContent = game.game_id;
  element("suite-name").textContent = game.suite;
  for (const [id, field] of Object.entries({
    prime: "p", "group-order": "q", generator: "g", "public-key": "y",
  })) element(id).textContent = game[field];
  element("wins").textContent = game.wins;
  element("wins-required").textContent = game.wins_required;
  element("query-count").textContent = game.queries;
  element("progress-fill").style.width = `${100 * game.wins / game.wins_required}%`;
}

function clearInstance() {
  element("transcript").replaceChildren();
  signatureInputs.forEach((input) => { input.value = ""; });
  element("oracle-server-status").textContent = "Waiting for a signing query.";
  element("victory").hidden = true;
  element("secret-output").textContent = "";
}

async function openGame() {
  setBusy(true);
  try {
    const game = await post("/api/v1/games");
    applyGame(game);
    element("connection-dot").classList.add("online");
    element("connection-label").textContent = "Server online";
    setStatus("Game ready. Collect signatures, then submit a fresh-message forgery.", "success");
  } catch (error) {
    element("connection-label").textContent = "Server unavailable";
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function resetGame() {
  if (!state.game) return openGame();
  setBusy(true);
  try {
    applyGame(await post(gamePath("reset")));
    clearInstance();
    element("result-indicator").textContent = "Awaiting a forgery";
    element("result-indicator").dataset.result = "neutral";
    element("forge-server-status").textContent = "The new instance has an empty query history.";
    setStatus("Fresh key and nonce ready. Query history cleared.", "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function queryOracle() {
  const message = normalizedHex(messageInputs[0].value);
  setBusy(true);
  setStatus("The Server is signing your chosen message…");
  try {
    const result = await post(gamePath("oracle"), { message_hex: message });
    state.game.queries = result.queries;
    element("query-count").textContent = result.queries;
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = `Query ${result.queries}`;
    item.append(title);
    for (const [label, value] of [["M (hex)", message || "(empty)"], ["R", result.R], ["s", result.s]]) {
      const row = document.createElement("div");
      const name = document.createElement("b");
      const code = document.createElement("code");
      name.textContent = label;
      code.textContent = value;
      row.append(name, code);
      item.append(row);
    }
    element("transcript").append(item);
    element("transcript").scrollTop = element("transcript").scrollHeight;
    element("oracle-server-status").textContent = "Signature returned. The nonce advanced by 10 modulo q.";
    element("forge-server-status").textContent = "A valid signature on a fresh message completes the game.";
    setStatus("Signature recorded. You may request another.", "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function submitForgery() {
  const body = {
    message_hex: normalizedHex(messageInputs[1].value),
    R: signatureInputs[0].value.trim(),
    s: signatureInputs[1].value.trim(),
  };
  setBusy(true);
  setStatus("The Server is checking the signature and message freshness…");
  try {
    const result = await post(gamePath("forge"), body);
    applyGame(result.game);
    if (result.valid) {
      element("result-indicator").textContent = "Valid and fresh · experiment complete";
      element("result-indicator").dataset.result = "correct";
      element("forge-server-status").textContent = "The fresh-message signature was accepted.";
      element("secret-output").textContent = result.secret;
      element("victory").hidden = false;
      setStatus("Forgery accepted. The Server revealed its secret.", "success");
    } else {
      clearInstance();
      element("result-indicator").textContent = result.fresh ? "Previous attempt: invalid signature" : "Previous attempt: message was queried";
      element("result-indicator").dataset.result = "incorrect";
      element("forge-server-status").textContent = "A new signing key and nonce sequence are ready. Query history is empty.";
      setStatus("Forgery rejected. Start again with the new public key above.", "error");
    }
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

[...messageInputs, ...signatureInputs].forEach((input) => input.addEventListener("input", updateControls));
element("reset-button").addEventListener("click", resetGame);
element("oracle-button").addEventListener("click", queryOracle);
element("forge-button").addEventListener("click", submitForgery);
updateControls();
openGame();
