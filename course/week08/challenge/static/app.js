"use strict";

const elements = {
  connectionDot: document.querySelector("#connection-dot"),
  connectionLabel: document.querySelector("#connection-label"),
  gameId: document.querySelector("#game-id"),
  suiteName: document.querySelector("#suite-name"),
  prime: document.querySelector("#prime"),
  generator: document.querySelector("#generator"),
  publicKey: document.querySelector("#public-key"),
  wins: document.querySelector("#wins"),
  winsRequired: document.querySelector("#wins-required"),
  progressFill: document.querySelector("#progress-fill"),
  statusMessage: document.querySelector("#status-message"),
  resetButton: document.querySelector("#reset-button"),
  leftMessage: document.querySelector("#left-message"),
  rightMessage: document.querySelector("#right-message"),
  challengeButton: document.querySelector("#challenge-button"),
  challengeResult: document.querySelector("#challenge-result"),
  challengeC1: document.querySelector("#challenge-c1"),
  challengeC2: document.querySelector("#challenge-c2"),
  challengeServerStatus: document.querySelector("#challenge-server-status"),
  guessButtons: [...document.querySelectorAll(".guess-button")],
  guessIndicator: document.querySelector("#guess-indicator"),
  victory: document.querySelector("#victory"),
  secretOutput: document.querySelector("#secret-output"),
};

const state = {
  gameId: null,
  p: null,
  activeChallenge: false,
  complete: false,
  busy: false,
};

async function fetchJson(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || "Request failed with status " + response.status + ".");
  return payload;
}

function jsonPost(body = {}) {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

function setStatus(message, kind = "neutral") {
  elements.statusMessage.textContent = message;
  elements.statusMessage.dataset.kind = kind;
}

function updateScore(wins, required) {
  elements.wins.textContent = wins;
  elements.winsRequired.textContent = required;
  elements.progressFill.style.width = Math.min(100, (wins / required) * 100) + "%";
}

function decimalCandidate(input) {
  const value = input.value.trim();
  if (!/^[0-9]+$/.test(value) || state.p === null) return null;
  const number = BigInt(value);
  if (number < 1n || number >= state.p) return null;
  return number.toString();
}

function updateControls() {
  const left = decimalCandidate(elements.leftMessage);
  const right = decimalCandidate(elements.rightMessage);
  const ready = Boolean(state.gameId) && !state.busy && !state.complete;
  elements.challengeButton.disabled = !ready || state.activeChallenge
    || left === null || right === null || left === right;
  elements.guessButtons.forEach((button) => {
    button.disabled = !ready || !state.activeChallenge;
  });
  elements.resetButton.disabled = !ready;
}

function setBusy(busy) {
  state.busy = busy;
  updateControls();
}

function applyGame(game) {
  state.gameId = game.game_id;
  state.p = BigInt(game.p);
  state.activeChallenge = false;
  state.complete = game.complete;
  elements.gameId.textContent = game.game_id;
  elements.suiteName.textContent = game.suite;
  elements.prime.textContent = game.p;
  elements.generator.textContent = game.g;
  elements.publicKey.textContent = game.h;
  updateScore(game.wins, game.wins_required);
  updateControls();
}

function clearRound() {
  state.activeChallenge = false;
  elements.challengeResult.hidden = true;
  elements.challengeC1.textContent = "";
  elements.challengeC2.textContent = "";
  elements.challengeServerStatus.textContent = "Waiting for two distinct integers.";
  elements.guessIndicator.textContent = "Awaiting a challenge";
  elements.guessIndicator.dataset.result = "neutral";
  updateControls();
}

async function openGame() {
  setBusy(true);
  try {
    const health = await fetchJson("/health");
    elements.connectionDot.classList.toggle("online", health.status === "ok");
    elements.connectionLabel.textContent = "Server online";
    const game = await fetchJson("/api/v1/games", jsonPost());
    applyGame(game);
    setStatus("Game ready. Choose two numbers for the challenge.", "success");
  } catch (error) {
    elements.connectionDot.classList.remove("online");
    elements.connectionLabel.textContent = "Server unavailable";
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function resetRound() {
  if (!state.gameId) return;
  setBusy(true);
  setStatus("Replacing the round key…");
  try {
    const game = await fetchJson("/api/v1/games/" + encodeURIComponent(state.gameId) + "/reset", jsonPost());
    applyGame(game);
    clearRound();
    setStatus("Round reset with a fresh key. Your streak remains " + game.wins + ".", "success");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function createChallenge() {
  const left = decimalCandidate(elements.leftMessage);
  const right = decimalCandidate(elements.rightMessage);
  if (!state.gameId || left === null || right === null || left === right || state.activeChallenge) return;
  setBusy(true);
  setStatus("The Server is choosing and encrypting one candidate…");
  try {
    const output = await fetchJson(
      "/api/v1/games/" + encodeURIComponent(state.gameId) + "/challenge",
      jsonPost({ left, right }),
    );
    state.activeChallenge = true;
    elements.challengeC1.textContent = output.c1;
    elements.challengeC2.textContent = output.c2;
    elements.challengeResult.hidden = false;
    elements.challengeServerStatus.textContent = "A hidden bit was sampled. Submit your guess below.";
    elements.guessIndicator.textContent = "Challenge active";
    elements.guessIndicator.dataset.result = "active";
    setStatus("Challenge ready. Inspect c₁ and c₂, then guess the hidden choice.", "success");
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
      "/api/v1/games/" + encodeURIComponent(state.gameId) + "/guess",
      jsonPost({ guess }),
    );
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
      elements.publicKey.textContent = result.h;
      clearRound();
      elements.guessIndicator.textContent = result.correct
        ? "Previous guess correct · streak " + result.wins
        : "Previous guess incorrect · streak reset";
      elements.guessIndicator.dataset.result = result.correct ? "correct" : "incorrect";
      setStatus(
        result.correct
          ? "Correct. The next round has a fresh public key."
          : "Incorrect. The streak returned to zero; the next round has a fresh public key.",
        result.correct ? "success" : "error",
      );
    }
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    setBusy(false);
  }
}

elements.leftMessage.addEventListener("input", updateControls);
elements.rightMessage.addEventListener("input", updateControls);
elements.challengeButton.addEventListener("click", createChallenge);
elements.resetButton.addEventListener("click", resetRound);
elements.guessButtons.forEach((button) => {
  button.addEventListener("click", () => submitGuess(Number(button.dataset.guess)));
});

updateControls();
openGame();
