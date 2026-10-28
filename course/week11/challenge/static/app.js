"use strict";

const element = (id) => document.getElementById(id);
const state = { game: null, busy: false };
const stages = ["server_hello", "client_accept", "relay_to_server", "relay_to_client", "guess", "complete"];
const descriptions = {
  server_hello: "1 of 5 · Deliver a ClientHello to the real Server.",
  client_accept: "2 of 5 · Deliver a server response to the honest Client.",
  relay_to_server: "3 of 5 · Relay the first client record to the real Server.",
  relay_to_client: "4 of 5 · Relay the server record back to the Client.",
  guess: "5 of 5 · Identify the second client plaintext.",
  complete: "The second client message was recovered.",
};

const operations = {
  server_hello: {
    input: "server-hello-input", button: "server-hello-button", field: "client_hello",
    path: "server-hello", output: "server-response-output", mirror: "real-server-response", next: "client-accept-input",
    result: "server_response", success: "The real Server answered. The next response is yours to deliver.",
  },
  client_accept: {
    input: "client-accept-input", button: "client-accept-button", field: "server_response",
    path: "client-accept", output: "first-client-record", mirror: "client-record-output", next: "relay-to-server-input",
    result: "record", success: "The Client accepted the handshake and sent the first message in its session.",
  },
  relay_to_server: {
    input: "relay-to-server-input", button: "relay-to-server-button", field: "record",
    path: "relay-to-server", output: "first-server-record", mirror: "server-record-output", next: "relay-to-client-input",
    result: "record", success: "The Server received the first message and sent an encrypted response.",
  },
  relay_to_client: {
    input: "relay-to-client-input", button: "relay-to-client-button", field: "record",
    path: "relay-to-client", output: "second-client-record", result: "record",
    success: "The Client sent a second message in that same session. Recover its exact plaintext.",
  },
};

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function normalizedHex(value) {
  if (!/^(?:[ \t\n\r\v\f]*[0-9a-f]{2})*[ \t\n\r\v\f]*$/i.test(value)) return null;
  return value.replace(/[ \t\n\r\v\f]/g, "").toLowerCase();
}

function setStatus(message, kind = "neutral") {
  element("status-message").textContent = message;
  element("status-message").dataset.kind = kind;
}

function updateControls() {
  const active = state.game && !state.game.complete ? state.game.stage : null;
  for (const [stage, operation] of Object.entries(operations)) {
    const input = element(operation.input);
    const enabled = active === stage && !state.busy;
    input.disabled = !enabled;
    let valid = false;
    if (enabled) {
      try {
        const parsed = JSON.parse(input.value);
        valid = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
      } catch (_error) {
        valid = false;
      }
    }
    element(operation.button).disabled = !enabled || !valid;
  }
  const guessEnabled = active === "guess" && !state.busy;
  element("guess-input").disabled = !guessEnabled;
  const guess = normalizedHex(element("guess-input").value);
  element("guess-button").disabled = !guessEnabled || guess === null || guess.length !== 64;
  element("reset-button").disabled = state.busy;
  for (const section of document.querySelectorAll(".exchange")) {
    section.dataset.active = String(section.dataset.stage === active);
  }
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

function clearExchange() {
  for (const id of [
    "server-response-output", "real-server-response", "first-client-record", "client-record-output",
    "first-server-record", "server-record-output", "second-client-record",
  ]) element(id).textContent = "Waiting for the preceding exchange…";
  for (const operation of Object.values(operations)) element(operation.input).value = "";
  element("guess-input").value = "";
  element("answer-result").textContent = "Awaiting the second client record.";
  element("victory").hidden = true;
  element("secret-output").textContent = "";
}

function applyGame(game, fresh = false) {
  state.game = game;
  if (fresh) clearExchange();
  element("game-id").textContent = game.game_id;
  element("suite-name").textContent = game.suite;
  element("wins").textContent = game.wins;
  element("wins-required").textContent = game.wins_required;
  element("progress-fill").style.width = `${100 * Math.max(0, stages.indexOf(game.stage)) / 5}%`;
  element("stage-description").textContent = descriptions[game.stage] || "Waiting for the next exchange.";
  element("group-id").textContent = String(game.group.id);
  element("group-p").textContent = game.group.p;
  element("group-q").textContent = game.group.q;
  element("group-g").textContent = game.group.g;
  element("certificate-details").textContent = pretty({
    root_public_key: game.root_public_key,
    certificate: game.certificate,
  });
  element("signing-key").textContent = game.compromised_root_signing_private_key;
  element("client-hello").textContent = pretty(game.client_hello);
  if (fresh) element("server-hello-input").value = pretty(game.client_hello);
  element("connection-dot").classList.add("online");
  element("connection-label").textContent = "Game connected";
  updateControls();
}

async function openGame() {
  setBusy(true);
  try {
    applyGame(await post("/api/v1/games"), true);
    setStatus("Game ready. The ClientHello has been copied into the first editor.", "success");
  } catch (error) {
    element("connection-dot").classList.remove("online");
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
    const game = await post(gamePath("reset"), { attempt_id: state.game.attempt_id });
    applyGame(game.game || game, true);
    setStatus("New attempt ready. The handshake and connection keys have changed.", "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function advance(stage) {
  const operation = operations[stage];
  let message;
  try {
    message = JSON.parse(element(operation.input).value);
  } catch (_error) {
    setStatus("Enter a valid JSON object for the current step.", "error");
    return;
  }
  setBusy(true);
  setStatus("Delivering the message…");
  try {
    const body = { attempt_id: state.game.attempt_id, [operation.field]: message };
    const result = await post(gamePath(operation.path), body);
    if (!result.accepted) {
      applyGame(result.game, true);
      setStatus("The message was rejected. A fresh attempt is ready.", "error");
      return;
    }
    const produced = result[operation.result];
    applyGame(result.game);
    element(operation.output).textContent = pretty(produced);
    if (operation.mirror) element(operation.mirror).textContent = pretty(produced);
    if (operation.next) element(operation.next).value = pretty(produced);
    setStatus(operation.success, "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function submitAnswer() {
  const answer = normalizedHex(element("guess-input").value);
  if (answer === null || answer.length !== 64) return;
  setBusy(true);
  setStatus("Checking the second client plaintext…");
  try {
    const result = await post(gamePath("guess"), { attempt_id: state.game.attempt_id, message_hex: answer });
    applyGame(result.game, !result.correct);
    if (result.correct) {
      element("answer-result").textContent = "Exact plaintext accepted.";
      element("secret-output").textContent = result.secret;
      element("victory").hidden = false;
      setStatus("You recovered the second client message.", "success");
    } else {
      setStatus("That was not the second client message. A fresh attempt is ready.", "error");
    }
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

for (const [stage, operation] of Object.entries(operations)) {
  element(operation.button).addEventListener("click", () => advance(stage));
  element(operation.input).addEventListener("input", updateControls);
}
element("guess-button").addEventListener("click", submitAnswer);
element("guess-input").addEventListener("input", updateControls);
element("reset-button").addEventListener("click", resetGame);
openGame();
