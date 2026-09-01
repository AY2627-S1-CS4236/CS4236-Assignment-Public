"use strict";

const elements = {
  connectionDot: document.querySelector("#connection-dot"),
  connectionLabel: document.querySelector("#connection-label"),
  gameId: document.querySelector("#game-id"),
  suiteName: document.querySelector("#suite-name"),
  wins: document.querySelector("#wins"),
  winsRequired: document.querySelector("#wins-required"),
  progressFill: document.querySelector("#progress-fill"),
  statusMessage: document.querySelector("#status-message"),
  resetButton: document.querySelector("#reset-button"),
  oracleMessage: document.querySelector("#oracle-message"),
  oracleCount: document.querySelector("#oracle-count"),
  oracleButton: document.querySelector("#oracle-button"),
  oracleResult: document.querySelector("#oracle-result"),
  oracleOutput: document.querySelector("#oracle-output"),
  oracleServerStatus: document.querySelector("#oracle-server-status"),
  forgeMessage: document.querySelector("#forge-message"),
  forgeCount: document.querySelector("#forge-count"),
  forgeTag: document.querySelector("#forge-tag"),
  tagCount: document.querySelector("#tag-count"),
  forgeButton: document.querySelector("#forge-button"),
  forgeServerStatus: document.querySelector("#forge-server-status"),
  resultIndicator: document.querySelector("#result-indicator"),
  victory: document.querySelector("#victory"),
  secretOutput: document.querySelector("#secret-output"),
};

const state = {
  gameId: null,
  groupBytes: 16,
  tagBytes: 32,
  wins: 0,
  winsRequired: 1,
  complete: false,
  busy: false,
};

elements.oracleMessage.value = "00".repeat(31);
elements.forgeMessage.value = "10".repeat(31);

async function fetchJson(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed with status ${response.status}.`);
  }
  return payload;
}

function jsonPost(body = {}) {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

function normalizedHex(value) {
  return value.replace(/\s+/g, "");
}

function byteLength(value) {
  const hex = normalizedHex(value);
  if (hex.length === 0) return 0;
  if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) return null;
  return hex.length / 2;
}

function renderTag(target, tagHex) {
  target.replaceChildren();
  const groupCharacters = state.groupBytes * 2;
  const groups = tagHex.match(new RegExp(`.{1,${groupCharacters}}`, "g")) || [];
  groups.forEach((group, index) => {
    const item = document.createElement("code");
    item.textContent = group;
    item.setAttribute("aria-label", `tag block ${index + 1}`);
    target.append(item);
  });
}

function updateScore(wins, required) {
  state.wins = wins;
  state.winsRequired = required;
  elements.wins.textContent = wins;
  elements.winsRequired.textContent = required;
  elements.progressFill.style.width = `${Math.min(100, (wins / required) * 100)}%`;
}

function setStatus(message, kind = "neutral") {
  elements.statusMessage.textContent = message;
  elements.statusMessage.dataset.kind = kind;
}

function setBusy(busy) {
  state.busy = busy;
  updateControls();
}

function updateControls() {
  const oracleLength = byteLength(elements.oracleMessage.value);
  const forgeLength = byteLength(elements.forgeMessage.value);
  const tagLength = byteLength(elements.forgeTag.value);

  elements.oracleCount.textContent = oracleLength ?? "—";
  elements.forgeCount.textContent = forgeLength ?? "—";
  elements.tagCount.textContent = tagLength ?? "—";

  const ready = Boolean(state.gameId) && !state.busy && !state.complete;
  elements.oracleButton.disabled = !ready
    || oracleLength === null
    || oracleLength > 4096;
  elements.forgeButton.disabled = !ready
    || forgeLength === null
    || forgeLength > 4096
    || tagLength !== state.tagBytes;
  elements.resetButton.disabled = !state.gameId || state.busy;
}

function applyGame(game) {
  state.gameId = game.game_id;
  state.groupBytes = game.suite.tag_group_bytes || game.suite.tag_bytes;
  state.tagBytes = game.suite.tag_bytes;
  state.complete = false;
  elements.gameId.textContent = game.game_id;
  elements.suiteName.textContent = game.suite.name;
  updateScore(game.wins, game.wins_required);
  updateControls();
}

function clearRoundOutputs() {
  elements.oracleResult.hidden = true;
  elements.oracleOutput.replaceChildren();
  elements.forgeTag.value = "";
  elements.oracleServerStatus.textContent = "Waiting for an oracle query.";
}

async function openGame() {
  setBusy(true);
  try {
    const health = await fetchJson("/health");
    elements.connectionDot.classList.toggle("online", health.status === "ok");
    elements.connectionLabel.textContent = "Server online";
    const game = await fetchJson("/api/v1/games", { method: "POST" });
    applyGame(game);
    setStatus("Game ready. Query the oracle and prepare a fresh forgery.", "success");
  } catch (error) {
    elements.connectionLabel.textContent = "Server unavailable";
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function resetRound() {
  if (!state.gameId) return;
  setBusy(true);
  setStatus("Generating a fresh secret key…");
  try {
    const game = await fetchJson(
      `/api/v1/games/${encodeURIComponent(state.gameId)}/reset`,
      { method: "POST" },
    );
    applyGame(game);
    clearRoundOutputs();
    elements.resultIndicator.textContent = "Awaiting a forgery";
    elements.resultIndicator.dataset.result = "neutral";
    elements.forgeServerStatus.textContent = "Game reset. Oracle history is empty.";
    setStatus("New key ready. The oracle history is empty.", "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function queryOracle() {
  if (!state.gameId) return;
  setBusy(true);
  setStatus("The Server is authenticating your chosen message…");
  try {
    const result = await fetchJson(
      `/api/v1/games/${encodeURIComponent(state.gameId)}/oracle`,
      jsonPost({ message_hex: normalizedHex(elements.oracleMessage.value) }),
    );
    renderTag(elements.oracleOutput, result.tag_hex);
    elements.oracleResult.hidden = false;
    elements.oracleServerStatus.textContent = "Tag returned. This exact message is now in the oracle history.";
    setStatus("Oracle tag returned. You may query again.", "success");
  } catch (error) {
    elements.oracleServerStatus.textContent = error.message;
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function submitForgery() {
  if (!state.gameId) return;
  setBusy(true);
  setStatus("The Server is checking validity and freshness…");
  try {
    const result = await fetchJson(
      `/api/v1/games/${encodeURIComponent(state.gameId)}/forge`,
      jsonPost({
        message_hex: normalizedHex(elements.forgeMessage.value),
        tag_hex: normalizedHex(elements.forgeTag.value),
      }),
    );
    state.complete = result.complete;
    updateScore(result.wins, result.wins_required);

    if (result.complete) {
      elements.resultIndicator.textContent = "Valid and fresh · experiment complete";
      elements.resultIndicator.dataset.result = "valid";
      elements.forgeServerStatus.textContent = "The fresh-message forgery was accepted.";
      elements.secretOutput.textContent = result.secret;
      elements.victory.hidden = false;
      setStatus("Forgery accepted. The secret is revealed.", "success");
    } else {
      clearRoundOutputs();
      elements.resultIndicator.textContent = result.fresh
        ? "Invalid tag · new key ready"
        : "Message was queried · new key ready";
      elements.resultIndicator.dataset.result = "invalid";
      elements.forgeServerStatus.textContent = result.fresh
        ? "The tag was invalid. A fresh-key round has started."
        : "The message was not fresh. A fresh-key round has started.";
      setStatus("Forgery rejected. Try again under the fresh key.", "error");
    }
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

elements.oracleMessage.addEventListener("input", updateControls);
elements.forgeMessage.addEventListener("input", updateControls);
elements.forgeTag.addEventListener("input", updateControls);
elements.oracleButton.addEventListener("click", queryOracle);
elements.forgeButton.addEventListener("click", submitForgery);
elements.resetButton.addEventListener("click", resetRound);

updateControls();
openGame();
