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
  encryptMessage: document.querySelector("#encrypt-message"),
  encryptAd: document.querySelector("#encrypt-ad"),
  encryptCount: document.querySelector("#encrypt-count"),
  encryptAdCount: document.querySelector("#encrypt-ad-count"),
  encryptButton: document.querySelector("#encrypt-button"),
  encryptResult: document.querySelector("#encrypt-result"),
  encryptIvOutput: document.querySelector("#encrypt-iv-output"),
  encryptAdOutput: document.querySelector("#encrypt-ad-output"),
  encryptCiphertextOutput: document.querySelector("#encrypt-ciphertext-output"),
  encryptTagOutput: document.querySelector("#encrypt-tag-output"),
  encryptServerStatus: document.querySelector("#encrypt-server-status"),
  leftMessage: document.querySelector("#left-message"),
  rightMessage: document.querySelector("#right-message"),
  challengeAd: document.querySelector("#challenge-ad"),
  leftCount: document.querySelector("#left-count"),
  rightCount: document.querySelector("#right-count"),
  challengeAdCount: document.querySelector("#challenge-ad-count"),
  challengeButton: document.querySelector("#challenge-button"),
  challengeResult: document.querySelector("#challenge-result"),
  challengeIvOutput: document.querySelector("#challenge-iv-output"),
  challengeAdOutput: document.querySelector("#challenge-ad-output"),
  challengeCiphertextOutput: document.querySelector("#challenge-ciphertext-output"),
  challengeTagOutput: document.querySelector("#challenge-tag-output"),
  challengeServerStatus: document.querySelector("#challenge-server-status"),
  decryptIv: document.querySelector("#decrypt-iv"),
  decryptAd: document.querySelector("#decrypt-ad"),
  decryptCiphertext: document.querySelector("#decrypt-ciphertext"),
  decryptTag: document.querySelector("#decrypt-tag"),
  decryptCiphertextCount: document.querySelector("#decrypt-ciphertext-count"),
  decryptButton: document.querySelector("#decrypt-button"),
  decryptIndicator: document.querySelector("#decrypt-indicator"),
  decryptResult: document.querySelector("#decrypt-result"),
  plaintextOutput: document.querySelector("#plaintext-output"),
  decryptServerStatus: document.querySelector("#decrypt-server-status"),
  guessButtons: [...document.querySelectorAll(".guess-button")],
  guessIndicator: document.querySelector("#guess-indicator"),
  victory: document.querySelector("#victory"),
  secretOutput: document.querySelector("#secret-output"),
};

const state = {
  gameId: null,
  wins: 0,
  winsRequired: 30,
  activeChallenge: false,
  complete: false,
  busy: false,
};

async function fetchJson(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed with status ${response.status}.`);
  return payload;
}

function jsonPost(body = {}) {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

function normalizedHex(value) { return value.replace(/\s+/g, ""); }

function byteLength(value) {
  const hex = normalizedHex(value);
  if (hex.length % 2 !== 0 || (hex && !/^[0-9a-f]+$/i.test(hex))) return null;
  return hex.length / 2;
}

function renderBytes(target, hex) {
  target.replaceChildren();
  const groups = hex.match(/.{1,32}/g) || [];
  if (groups.length === 0) {
    const empty = document.createElement("code");
    empty.textContent = "(empty)";
    target.append(empty);
    return;
  }
  groups.forEach((group, index) => {
    const item = document.createElement("code");
    item.textContent = group;
    item.setAttribute("aria-label", `byte group ${index + 1}`);
    target.append(item);
  });
}

function setStatus(message, kind = "neutral") {
  elements.statusMessage.textContent = message;
  elements.statusMessage.dataset.kind = kind;
}

function updateScore(wins, required) {
  state.wins = wins;
  state.winsRequired = required;
  elements.wins.textContent = wins;
  elements.winsRequired.textContent = required;
  elements.progressFill.style.width = `${Math.min(100, (wins / required) * 100)}%`;
}

function setBusy(busy) { state.busy = busy; updateControls(); }

function updateControls() {
  const encryptLength = byteLength(elements.encryptMessage.value);
  const encryptAdLength = byteLength(elements.encryptAd.value);
  const leftLength = byteLength(elements.leftMessage.value);
  const rightLength = byteLength(elements.rightMessage.value);
  const challengeAdLength = byteLength(elements.challengeAd.value);
  const decryptIvLength = byteLength(elements.decryptIv.value);
  const decryptAdLength = byteLength(elements.decryptAd.value);
  const decryptCiphertextLength = byteLength(elements.decryptCiphertext.value);
  const decryptTagLength = byteLength(elements.decryptTag.value);

  elements.encryptCount.textContent = encryptLength ?? "—";
  elements.encryptAdCount.textContent = encryptAdLength ?? "—";
  elements.leftCount.textContent = leftLength ?? "—";
  elements.rightCount.textContent = rightLength ?? "—";
  elements.challengeAdCount.textContent = challengeAdLength ?? "—";
  elements.decryptCiphertextCount.textContent = decryptCiphertextLength ?? "—";

  const ready = Boolean(state.gameId) && !state.busy && !state.complete;
  elements.encryptButton.disabled = !ready || encryptLength === null || encryptLength > 4096
    || encryptAdLength === null || encryptAdLength > 15;
  const candidatesValid = leftLength !== null && rightLength !== null
    && leftLength === rightLength && leftLength <= 4096
    && normalizedHex(elements.leftMessage.value).toLowerCase() !== normalizedHex(elements.rightMessage.value).toLowerCase();
  elements.challengeButton.disabled = !ready || state.activeChallenge || !candidatesValid
    || challengeAdLength === null || challengeAdLength > 15;
  elements.decryptButton.disabled = !ready || decryptIvLength !== 8
    || decryptAdLength === null || decryptAdLength > 15
    || decryptCiphertextLength === null || decryptCiphertextLength > 4128 || decryptTagLength !== 16;
  elements.guessButtons.forEach((button) => { button.disabled = !ready || !state.activeChallenge; });
  elements.resetButton.disabled = !state.gameId || state.busy;
}

function applyGame(game) {
  state.gameId = game.game_id;
  state.activeChallenge = false;
  state.complete = game.complete;
  elements.gameId.textContent = game.game_id;
  elements.suiteName.textContent = game.suite.name;
  updateScore(game.wins, game.wins_required);
  updateControls();
}

function clearRound() {
  state.activeChallenge = false;
  elements.challengeResult.hidden = true;
  elements.challengeIvOutput.textContent = "";
  elements.challengeAdOutput.textContent = "";
  elements.challengeCiphertextOutput.replaceChildren();
  elements.challengeTagOutput.textContent = "";
  elements.decryptIv.value = "";
  elements.decryptAd.value = "";
  elements.decryptCiphertext.value = "";
  elements.decryptTag.value = "";
  elements.decryptResult.hidden = true;
  elements.plaintextOutput.replaceChildren();
  elements.decryptIndicator.textContent = "Awaiting a modified tuple";
  elements.decryptIndicator.dataset.result = "neutral";
  elements.guessIndicator.textContent = "Awaiting a challenge";
  elements.guessIndicator.dataset.result = "neutral";
  elements.challengeServerStatus.textContent = "Waiting for two distinct, equal-length candidates.";
  elements.decryptServerStatus.textContent = "A valid tuple returns the complete plaintext.";
  updateControls();
}

async function openGame() {
  setBusy(true);
  try {
    const health = await fetchJson("/health");
    elements.connectionDot.classList.toggle("online", health.status === "ok");
    elements.connectionLabel.textContent = "Server online";
    const game = await fetchJson("/api/v1/games", { method: "POST" });
    applyGame(game);
    setStatus("Game ready. Create a challenge or inspect the encryption oracle.", "success");
  } catch (error) {
    elements.connectionLabel.textContent = "Server unavailable";
    setStatus(error.message, "error");
  } finally { setBusy(false); }
}

async function resetRound() {
  if (!state.gameId) return;
  setBusy(true);
  setStatus("Replacing the round key…");
  try {
    const game = await fetchJson(`/api/v1/games/${encodeURIComponent(state.gameId)}/reset`, { method: "POST" });
    applyGame(game);
    clearRound();
    setStatus(`Round reset with a fresh key. Your streak remains ${game.wins}.`, "success");
  } catch (error) { setStatus(error.message, "error"); }
  finally { setBusy(false); }
}

function showAead(prefix, result) {
  elements[`${prefix}IvOutput`].textContent = result.iv_hex;
  elements[`${prefix}AdOutput`].textContent = result.associated_data_hex;
  renderBytes(elements[`${prefix}CiphertextOutput`], result.ciphertext_hex);
  elements[`${prefix}TagOutput`].textContent = result.tag_hex;
  elements[`${prefix}Result`].hidden = false;
}

async function encryptOracle() {
  if (!state.gameId) return;
  setBusy(true);
  setStatus("The Server is encrypting with a fresh IV…");
  try {
    const result = await fetchJson(`/api/v1/games/${encodeURIComponent(state.gameId)}/oracle/encrypt`, jsonPost({
      message_hex: normalizedHex(elements.encryptMessage.value),
      associated_data_hex: normalizedHex(elements.encryptAd.value),
    }));
    showAead("encrypt", result);
    elements.encryptServerStatus.textContent = "Four components returned. Query again to observe a fresh IV.";
    setStatus("Encryption oracle returned IV, AD, ciphertext, and tag.", "success");
  } catch (error) {
    elements.encryptServerStatus.textContent = error.message;
    setStatus(error.message, "error");
  } finally { setBusy(false); }
}

async function createChallenge() {
  if (!state.gameId || state.activeChallenge) return;
  setBusy(true);
  setStatus("The Server is choosing and encrypting one candidate…");
  try {
    const result = await fetchJson(`/api/v1/games/${encodeURIComponent(state.gameId)}/challenge`, jsonPost({
      left_hex: normalizedHex(elements.leftMessage.value),
      right_hex: normalizedHex(elements.rightMessage.value),
      associated_data_hex: normalizedHex(elements.challengeAd.value),
    }));
    state.activeChallenge = true;
    showAead("challenge", result);
    elements.decryptIv.value = result.iv_hex;
    elements.decryptAd.value = result.associated_data_hex;
    elements.decryptCiphertext.value = result.ciphertext_hex;
    elements.decryptTag.value = result.tag_hex;
    elements.challengeServerStatus.textContent = "A hidden bit was sampled. The exact tuple is now forbidden to the decryption oracle.";
    elements.guessIndicator.textContent = "Challenge active";
    elements.guessIndicator.dataset.result = "active";
    setStatus("Challenge ready. Use the available oracles to investigate the hidden choice.", "success");
  } catch (error) {
    elements.challengeServerStatus.textContent = error.message;
    setStatus(error.message, "error");
  } finally { setBusy(false); }
}

async function decryptOracle() {
  if (!state.gameId) return;
  setBusy(true);
  setStatus("The Server is checking the submitted tag…");
  try {
    const result = await fetchJson(`/api/v1/games/${encodeURIComponent(state.gameId)}/oracle/decrypt`, jsonPost({
      iv_hex: normalizedHex(elements.decryptIv.value),
      associated_data_hex: normalizedHex(elements.decryptAd.value),
      ciphertext_hex: normalizedHex(elements.decryptCiphertext.value),
      tag_hex: normalizedHex(elements.decryptTag.value),
    }));
    if (result.valid) {
      renderBytes(elements.plaintextOutput, result.plaintext_hex);
      elements.decryptResult.hidden = false;
      elements.decryptIndicator.textContent = "Valid tag · plaintext returned";
      elements.decryptIndicator.dataset.result = "correct";
      elements.decryptServerStatus.textContent = "The decryption oracle returned the submitted tuple's plaintext.";
      setStatus("The submitted tuple authenticated and its plaintext was returned.", "success");
    } else {
      elements.decryptResult.hidden = true;
      elements.decryptIndicator.textContent = "Invalid tag · no plaintext";
      elements.decryptIndicator.dataset.result = "incorrect";
      elements.decryptServerStatus.textContent = "The submitted public components did not reproduce the tag.";
      setStatus("Authentication failed. Review the submitted tuple and try again.", "error");
    }
  } catch (error) {
    elements.decryptResult.hidden = true;
    elements.decryptIndicator.textContent = "Query rejected";
    elements.decryptIndicator.dataset.result = "incorrect";
    elements.decryptServerStatus.textContent = error.message;
    setStatus(error.message, "error");
  } finally { setBusy(false); }
}

async function submitGuess(guess) {
  if (!state.gameId || !state.activeChallenge) return;
  setBusy(true);
  try {
    const result = await fetchJson(`/api/v1/games/${encodeURIComponent(state.gameId)}/guess`, jsonPost({ guess }));
    state.complete = result.complete;
    updateScore(result.wins, result.wins_required);
    if (result.complete) {
      state.activeChallenge = false;
      elements.guessIndicator.textContent = "Correct · experiment complete";
      elements.guessIndicator.dataset.result = "correct";
      elements.secretOutput.textContent = result.secret;
      elements.victory.hidden = false;
      setStatus("Thirty consecutive guesses were correct. The secret is revealed.", "success");
    } else {
      const message = result.correct
        ? `Correct. Your streak is ${result.wins}; the next round has a fresh key.`
        : "Incorrect. The streak returned to zero; the next round has a fresh key.";
      clearRound();
      elements.guessIndicator.textContent = result.correct ? `Previous guess correct · streak ${result.wins}` : "Previous guess incorrect · streak reset";
      elements.guessIndicator.dataset.result = result.correct ? "correct" : "incorrect";
      setStatus(message, result.correct ? "success" : "error");
    }
  } catch (error) { setStatus(error.message, "error"); }
  finally { setBusy(false); }
}

[
  elements.encryptMessage, elements.encryptAd, elements.leftMessage,
  elements.rightMessage, elements.challengeAd, elements.decryptIv,
  elements.decryptAd, elements.decryptCiphertext, elements.decryptTag,
].forEach((input) => input.addEventListener("input", updateControls));
elements.encryptButton.addEventListener("click", encryptOracle);
elements.challengeButton.addEventListener("click", createChallenge);
elements.decryptButton.addEventListener("click", decryptOracle);
elements.resetButton.addEventListener("click", resetRound);
elements.guessButtons.forEach((button) => button.addEventListener("click", () => submitGuess(Number(button.dataset.guess))));

updateControls();
openGame();
