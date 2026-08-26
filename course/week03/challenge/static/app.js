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
  oracleIvOutput: document.querySelector("#oracle-iv-output"),
  oracleOutput: document.querySelector("#oracle-output"),
  oracleServerStatus: document.querySelector("#oracle-server-status"),
  postOracleMessage: document.querySelector("#post-oracle-message"),
  postOracleCount: document.querySelector("#post-oracle-count"),
  postOracleButton: document.querySelector("#post-oracle-button"),
  postOracleResult: document.querySelector("#post-oracle-result"),
  postOracleIvOutput: document.querySelector("#post-oracle-iv-output"),
  postOracleOutput: document.querySelector("#post-oracle-output"),
  postOracleServerStatus: document.querySelector("#post-oracle-server-status"),
  leftMessage: document.querySelector("#left-message"),
  rightMessage: document.querySelector("#right-message"),
  leftCount: document.querySelector("#left-count"),
  rightCount: document.querySelector("#right-count"),
  challengeButton: document.querySelector("#challenge-button"),
  challengeResult: document.querySelector("#challenge-result"),
  challengeIvOutput: document.querySelector("#challenge-iv-output"),
  challengeOutput: document.querySelector("#challenge-output"),
  challengeServerStatus: document.querySelector("#challenge-server-status"),
  guessButtons: [...document.querySelectorAll(".guess-button")],
  resultIndicator: document.querySelector("#result-indicator"),
  victory: document.querySelector("#victory"),
  secretOutput: document.querySelector("#secret-output"),
};

const state = {
  gameId: null,
  groupBytes: null,
  wins: 0,
  winsRequired: 30,
  activeChallenge: false,
  complete: false,
  busy: false,
};

elements.oracleMessage.value = `${"00".repeat(16)}${"10".repeat(16)}`;
elements.postOracleMessage.value = `${"00".repeat(16)}${"50".repeat(16)}`;
elements.leftMessage.value = `${"00".repeat(16)}${"20".repeat(16)}`;
elements.rightMessage.value = `${"30".repeat(16)}${"40".repeat(16)}`;

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
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) return null;
  return hex.length / 2;
}

function renderCiphertext(target, ciphertextHex) {
  target.replaceChildren();
  const groupCharacters = Number.isInteger(state.groupBytes) && state.groupBytes > 0
    ? state.groupBytes * 2
    : ciphertextHex.length;
  const groups = ciphertextHex.match(new RegExp(`.{1,${groupCharacters}}`, "g")) || [];
  groups.forEach((group, index) => {
    const item = document.createElement("code");
    item.textContent = group;
    item.setAttribute("aria-label", `ciphertext group ${index}`);
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
  const postOracleLength = byteLength(elements.postOracleMessage.value);
  const leftLength = byteLength(elements.leftMessage.value);
  const rightLength = byteLength(elements.rightMessage.value);

  elements.oracleCount.textContent = oracleLength ?? "—";
  elements.postOracleCount.textContent = postOracleLength ?? "—";
  elements.leftCount.textContent = leftLength ?? "—";
  elements.rightCount.textContent = rightLength ?? "—";

  const ready = Boolean(state.gameId) && !state.busy && !state.complete;
  elements.oracleButton.disabled = !ready
    || state.activeChallenge
    || oracleLength === null
    || oracleLength === 0
    || oracleLength > 4096;
  elements.postOracleButton.disabled = !ready
    || !state.activeChallenge
    || postOracleLength === null
    || postOracleLength === 0
    || postOracleLength > 4096;

  const candidatesValid = leftLength !== null
    && rightLength !== null
    && leftLength > 0
    && leftLength === rightLength
    && leftLength <= 4096
    && normalizedHex(elements.leftMessage.value).toLowerCase()
      !== normalizedHex(elements.rightMessage.value).toLowerCase();
  elements.challengeButton.disabled = !ready || state.activeChallenge || !candidatesValid;
  elements.guessButtons.forEach((button) => {
    button.disabled = !ready || !state.activeChallenge;
  });
  elements.resetButton.disabled = !state.gameId || state.busy;
}

function applyGame(game) {
  state.gameId = game.game_id;
  state.groupBytes = game.suite.ciphertext_group_bytes;
  state.activeChallenge = false;
  state.complete = false;
  elements.gameId.textContent = game.game_id;
  elements.suiteName.textContent = game.suite.name;
  updateScore(game.wins, game.wins_required);
  updateControls();
}

function clearExperimentOutputs() {
  elements.oracleResult.hidden = true;
  elements.oracleIvOutput.textContent = "";
  elements.oracleOutput.replaceChildren();
  elements.postOracleResult.hidden = true;
  elements.postOracleIvOutput.textContent = "";
  elements.postOracleOutput.replaceChildren();
  elements.challengeResult.hidden = true;
  elements.challengeIvOutput.textContent = "";
  elements.challengeOutput.replaceChildren();
  elements.victory.hidden = true;
  elements.secretOutput.textContent = "";
  elements.oracleServerStatus.textContent = "Waiting for pre-challenge oracle queries.";
  elements.postOracleServerStatus.textContent = "This phase opens after the challenge ciphertext is returned.";
  elements.challengeServerStatus.textContent = "Waiting for two challenge candidates.";
  elements.resultIndicator.textContent = "Awaiting a guess";
  elements.resultIndicator.dataset.result = "neutral";
}

async function openGame() {
  setBusy(true);
  try {
    const health = await fetchJson("/health");
    elements.connectionDot.classList.toggle("online", health.status === "ok");
    elements.connectionLabel.textContent = "Server online";
    const game = await fetchJson("/api/v1/games", { method: "POST" });
    applyGame(game);
    setStatus("Game ready. Query the oracle or prepare a challenge.", "success");
  } catch (error) {
    elements.connectionLabel.textContent = "Server unavailable";
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function resetGame() {
  if (!state.gameId) return;
  setBusy(true);
  setStatus("Generating a new key and IV…");
  try {
    const game = await fetchJson(
      `/api/v1/games/${encodeURIComponent(state.gameId)}/reset`,
      { method: "POST" },
    );
    applyGame(game);
    clearExperimentOutputs();
    setStatus(`Game reset with a new key and IV. Your streak remains ${game.wins}.`, "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function queryOracle(phase) {
  if (!state.gameId) return;
  const postChallenge = phase === "post";
  const message = postChallenge ? elements.postOracleMessage : elements.oracleMessage;
  const resultPanel = postChallenge ? elements.postOracleResult : elements.oracleResult;
  const ivOutput = postChallenge ? elements.postOracleIvOutput : elements.oracleIvOutput;
  const ciphertextOutput = postChallenge ? elements.postOracleOutput : elements.oracleOutput;
  const serverStatus = postChallenge
    ? elements.postOracleServerStatus
    : elements.oracleServerStatus;
  setBusy(true);
  setStatus(`The Server is encrypting a ${postChallenge ? "post" : "pre"}-challenge oracle message…`);
  try {
    const result = await fetchJson(
      `/api/v1/games/${encodeURIComponent(state.gameId)}/oracle`,
      jsonPost({ message_hex: normalizedHex(message.value) }),
    );
    ivOutput.textContent = result.iv_hex;
    renderCiphertext(ciphertextOutput, result.ciphertext_hex);
    resultPanel.hidden = false;
    serverStatus.textContent = "Query recorded. You may query again; this exact message is restricted from challenges.";
    setStatus(`${postChallenge ? "Post" : "Pre"}-challenge oracle response returned. You may query again.`, "success");
  } catch (error) {
    serverStatus.textContent = error.message;
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function createChallenge() {
  if (!state.gameId || state.activeChallenge) return;
  setBusy(true);
  setStatus("The Server is choosing and encrypting one candidate…");
  try {
    const result = await fetchJson(
      `/api/v1/games/${encodeURIComponent(state.gameId)}/challenge`,
      jsonPost({
        left_hex: normalizedHex(elements.leftMessage.value),
        right_hex: normalizedHex(elements.rightMessage.value),
      }),
    );
    state.activeChallenge = true;
    elements.challengeIvOutput.textContent = result.iv_hex;
    renderCiphertext(elements.challengeOutput, result.ciphertext_hex);
    elements.challengeResult.hidden = false;
    elements.challengeServerStatus.textContent = "A hidden bit was sampled. Both exact candidates are now restricted from oracle queries.";
    elements.resultIndicator.textContent = "Challenge active";
    elements.resultIndicator.dataset.result = "active";
    setStatus("Challenge ciphertext ready. Compare the outputs and guess the hidden bit.", "success");
  } catch (error) {
    elements.challengeServerStatus.textContent = error.message;
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function submitGuess(guess) {
  if (!state.gameId || !state.activeChallenge) return;
  setBusy(true);
  try {
    const result = await fetchJson(
      `/api/v1/games/${encodeURIComponent(state.gameId)}/guess`,
      jsonPost({ guess }),
    );
    state.activeChallenge = false;
    state.complete = result.complete;
    updateScore(result.wins, result.wins_required);

    if (!result.complete) {
      clearExperimentOutputs();
    }

    if (result.complete) {
      elements.resultIndicator.textContent = "Correct · experiment complete";
      elements.resultIndicator.dataset.result = "correct";
      elements.secretOutput.textContent = result.secret;
      elements.victory.hidden = false;
      setStatus("Thirty consecutive guesses were correct. The secret is revealed.", "success");
    } else if (result.correct) {
      elements.resultIndicator.textContent = `Correct · streak ${result.wins}`;
      elements.resultIndicator.dataset.result = "correct";
      setStatus(`Correct. Your streak is ${result.wins}; a new game started with a fresh key and IV.`, "success");
    } else {
      elements.resultIndicator.textContent = "Incorrect · streak reset";
      elements.resultIndicator.dataset.result = "incorrect";
      setStatus("Incorrect. The streak returned to zero, and a new game started with a fresh key and IV.", "error");
    }
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

elements.oracleMessage.addEventListener("input", updateControls);
elements.postOracleMessage.addEventListener("input", updateControls);
elements.leftMessage.addEventListener("input", updateControls);
elements.rightMessage.addEventListener("input", updateControls);
elements.oracleButton.addEventListener("click", () => queryOracle("pre"));
elements.postOracleButton.addEventListener("click", () => queryOracle("post"));
elements.challengeButton.addEventListener("click", createChallenge);
elements.resetButton.addEventListener("click", resetGame);
elements.guessButtons.forEach((button) => {
  button.addEventListener("click", () => submitGuess(Number(button.dataset.guess)));
});

updateControls();
openGame();
