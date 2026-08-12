"use strict";

const elements = {
  serviceState: document.querySelector("#service-state"),
  serviceLabel: document.querySelector("#service-label"),
  backupForm: document.querySelector("#backup-form"),
  backupText: document.querySelector("#backup-text"),
  characterCount: document.querySelector("#character-count"),
  backupMessage: document.querySelector("#backup-message"),
  backupSubmit: document.querySelector("#backup-submit"),
  seedResult: document.querySelector("#seed-result"),
  createdSeed: document.querySelector("#created-seed"),
  createdRecordId: document.querySelector("#created-record-id"),
  copySeed: document.querySelector("#copy-seed"),
  copyRecordId: document.querySelector("#copy-record-id"),
  refreshButton: document.querySelector("#refresh-button"),
  archiveStatus: document.querySelector("#archive-status"),
  archiveList: document.querySelector("#archive-list"),
  restoreForm: document.querySelector("#restore-form"),
  restoreRecordId: document.querySelector("#restore-record-id"),
  restoreSeed: document.querySelector("#restore-seed"),
  restoreMessage: document.querySelector("#restore-message"),
  restoreSubmit: document.querySelector("#restore-submit"),
  restoredOutput: document.querySelector("#restored-output"),
  restoredText: document.querySelector("#restored-text"),
  copyRestored: document.querySelector("#copy-restored"),
};

const state = {
  backups: [],
  creating: false,
  restoring: false,
};

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed with status ${response.status}.`);
  }
  return data;
}

function setButtonBusy(button, busy, busyLabel, readyLabel) {
  button.disabled = busy;
  button.classList.toggle("is-busy", busy);
  button.querySelector("span:first-child").textContent = busy ? busyLabel : readyLabel;
}

function setServiceStatus(online) {
  elements.serviceState.classList.toggle("is-online", online);
  elements.serviceState.classList.toggle("is-offline", !online);
  elements.serviceLabel.textContent = online ? "All systems online" : "Service unavailable";
}

function createArchiveRecord(record, index) {
  const article = document.createElement("article");
  article.className = "archive-record";

  const indexNode = document.createElement("span");
  indexNode.className = "record-index";
  indexNode.textContent = String(index + 1).padStart(2, "0");

  const details = document.createElement("div");
  details.className = "record-details";

  const meta = document.createElement("div");
  meta.className = "record-meta";

  const id = document.createElement("code");
  id.textContent = record.record_id;

  const time = document.createElement("time");
  time.dateTime = record.created_at;
  time.title = record.created_at;
  time.textContent = formatDate(record.created_at);

  meta.append(id, time);

  const cipher = document.createElement("code");
  cipher.className = "record-cipher";
  cipher.textContent = record.ciphertext_hex;

  details.append(meta, cipher);

  const useButton = document.createElement("button");
  useButton.className = "use-button";
  useButton.type = "button";
  useButton.textContent = "Restore";
  useButton.addEventListener("click", () => {
    elements.restoreRecordId.value = record.record_id;
    elements.restoreSeed.focus();
    document.querySelector("#restore").scrollIntoView({ behavior: "smooth" });
  });

  article.append(indexNode, details, useButton);
  return article;
}

function renderArchive() {
  elements.archiveList.replaceChildren();
  if (state.backups.length === 0) {
    elements.archiveStatus.hidden = false;
    elements.archiveStatus.textContent = "No encrypted records have been stored yet.";
    return;
  }

  elements.archiveStatus.hidden = true;
  state.backups.forEach((record, index) => {
    elements.archiveList.append(createArchiveRecord(record, index));
  });
}

async function loadArchive() {
  elements.refreshButton.disabled = true;
  elements.refreshButton.classList.add("is-busy");
  elements.archiveStatus.hidden = false;
  elements.archiveStatus.textContent = "Loading encrypted records…";

  try {
    const data = await fetchJson("/api/v1/backups");
    state.backups = data.backups;
    renderArchive();
  } catch (error) {
    elements.archiveList.replaceChildren();
    elements.archiveStatus.textContent = error.message;
  } finally {
    elements.refreshButton.disabled = false;
    elements.refreshButton.classList.remove("is-busy");
  }
}

async function checkHealth() {
  try {
    const health = await fetchJson("/health");
    setServiceStatus(health.status === "ok");
  } catch {
    setServiceStatus(false);
  }
}

async function createBackup(event) {
  event.preventDefault();
  const text = elements.backupText.value;
  if (!text) {
    elements.backupMessage.textContent = "Enter some text before creating a backup.";
    elements.backupText.focus();
    return;
  }

  state.creating = true;
  elements.backupMessage.textContent = "";
  setButtonBusy(elements.backupSubmit, true, "Encrypting…", "Encrypt & store");

  try {
    const result = await fetchJson("/api/v1/backups", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    elements.createdSeed.textContent = result.seed_hex;
    elements.createdRecordId.textContent = result.record_id;
    elements.seedResult.hidden = false;
    elements.backupText.value = "";
    elements.characterCount.textContent = "0 characters";
    elements.restoreRecordId.value = result.record_id;
    elements.restoreSeed.value = result.seed_hex;
    elements.backupMessage.textContent = "Backup encrypted and added to the archive.";
    elements.backupMessage.classList.add("is-success");
    elements.seedResult.scrollIntoView({ behavior: "smooth", block: "center" });
    await loadArchive();
  } catch (error) {
    elements.backupMessage.textContent = error.message;
    elements.backupMessage.classList.remove("is-success");
  } finally {
    state.creating = false;
    setButtonBusy(elements.backupSubmit, false, "Encrypting…", "Encrypt & store");
  }
}

async function restoreBackup(event) {
  event.preventDefault();
  const recordId = elements.restoreRecordId.value.trim();
  const seedHex = elements.restoreSeed.value.trim();
  elements.restoredOutput.hidden = true;
  elements.restoreMessage.classList.remove("is-success");

  if (!recordId) {
    elements.restoreMessage.textContent = "Choose or enter a backup record ID.";
    elements.restoreRecordId.focus();
    return;
  }
  if (!/^[0-9a-f]{32}$/i.test(seedHex)) {
    elements.restoreMessage.textContent = "Enter the 32-character hexadecimal recovery seed.";
    elements.restoreSeed.focus();
    return;
  }

  state.restoring = true;
  elements.restoreMessage.textContent = "";
  setButtonBusy(elements.restoreSubmit, true, "Restoring…", "Restore backup");

  try {
    const result = await fetchJson("/api/v1/backups/restore", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ record_id: recordId, seed_hex: seedHex }),
    });
    elements.restoredText.textContent = result.text;
    elements.restoredOutput.hidden = false;
    elements.restoreMessage.textContent = "Backup restored successfully.";
    elements.restoreMessage.classList.add("is-success");
  } catch (error) {
    elements.restoreMessage.textContent = error.message;
  } finally {
    state.restoring = false;
    setButtonBusy(elements.restoreSubmit, false, "Restoring…", "Restore backup");
  }
}

async function copyText(value, button) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    const original = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => { button.textContent = original; }, 1400);
  } catch {
    button.textContent = "Copy unavailable";
  }
}

elements.backupText.addEventListener("input", () => {
  const count = [...elements.backupText.value].length;
  elements.characterCount.textContent = `${count} character${count === 1 ? "" : "s"}`;
  elements.backupMessage.textContent = "";
  elements.backupMessage.classList.remove("is-success");
});
elements.backupForm.addEventListener("submit", createBackup);
elements.restoreForm.addEventListener("submit", restoreBackup);
elements.refreshButton.addEventListener("click", loadArchive);
elements.copySeed.addEventListener("click", () => {
  copyText(elements.createdSeed.textContent, elements.copySeed);
});
elements.copyRecordId.addEventListener("click", () => {
  copyText(elements.createdRecordId.textContent, elements.copyRecordId);
});
elements.copyRestored.addEventListener("click", () => {
  copyText(elements.restoredText.textContent, elements.copyRestored);
});

checkHealth();
loadArchive();
