import { generateExternalId } from "./formatters.js";

export const SESSION_KEY = "aws_clarity_session_v2";
export const CONNECTION_PREFS_KEY = "aws_clarity_connection_prefs_v1";
const LEGACY_EXTERNAL_ID_KEY = "aws_clarity_external_id";

const ACCOUNT_FROM_ARN_RE = /^arn:aws:iam::(\d{12}):role\//;

export function extractAccountIdFromArn(roleArn) {
  if (typeof roleArn !== "string") return "";
  const match = roleArn.trim().match(ACCOUNT_FROM_ARN_RE);
  return match ? match[1] : "";
}

function readConnectionPrefs() {
  try {
    const raw = localStorage.getItem(CONNECTION_PREFS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        return {
          defaultExternalId:
            typeof parsed.defaultExternalId === "string" && parsed.defaultExternalId.trim()
              ? parsed.defaultExternalId.trim()
              : "",
          lastRoleArn: typeof parsed.lastRoleArn === "string" ? parsed.lastRoleArn.trim() : "",
          accountExternalIds:
            parsed.accountExternalIds && typeof parsed.accountExternalIds === "object"
              ? { ...parsed.accountExternalIds }
              : {},
        };
      }
    }
  } catch {
    // Ignore storage read errors
  }

  // Migrate any legacy sessionStorage External ID once so existing users keep their ID
  let migratedId = "";
  try {
    migratedId = (sessionStorage.getItem(LEGACY_EXTERNAL_ID_KEY) || "").trim();
  } catch {
    // Ignore storage errors
  }

  return {
    defaultExternalId: migratedId,
    lastRoleArn: "",
    accountExternalIds: {},
  };
}

function writeConnectionPrefs(prefs) {
  try {
    localStorage.setItem(CONNECTION_PREFS_KEY, JSON.stringify(prefs));
  } catch {
    // Ignore quota/privacy-mode errors
  }
}

/**
 * Returns a stable External ID for the given Role ARN / AWS account.
 * - Never regenerated automatically on every browser session.
 * - Remembered per 12-digit AWS Account ID once entered.
 * - Never stores AWS access keys, secret keys, or temporary STS tokens.
 */
export function getStableExternalId(roleArn = "") {
  const prefs = readConnectionPrefs();
  const accountId = extractAccountIdFromArn(roleArn);

  if (accountId && prefs.accountExternalIds[accountId]) {
    return prefs.accountExternalIds[accountId];
  }

  if (!prefs.defaultExternalId) {
    prefs.defaultExternalId = generateExternalId();
    writeConnectionPrefs(prefs);
  }

  return prefs.defaultExternalId;
}

export function getRememberedRoleArn() {
  return readConnectionPrefs().lastRoleArn || "";
}

export function saveConnectionDetails(roleArn, externalId) {
  const cleanedExtId = String(externalId || "").trim();
  const cleanedArn = String(roleArn || "").trim();
  const prefs = readConnectionPrefs();

  if (cleanedExtId) {
    const accountId = extractAccountIdFromArn(cleanedArn);
    if (accountId) {
      prefs.accountExternalIds[accountId] = cleanedExtId;
    } else {
      prefs.defaultExternalId = cleanedExtId;
    }
    if (!prefs.defaultExternalId) {
      prefs.defaultExternalId = cleanedExtId;
    }
  }

  if (cleanedArn) {
    prefs.lastRoleArn = cleanedArn;
  }

  writeConnectionPrefs(prefs);
}

export function regenerateStableExternalId(roleArn = "") {
  const fresh = generateExternalId();
  const prefs = readConnectionPrefs();
  const accountId = extractAccountIdFromArn(roleArn);
  if (accountId) {
    prefs.accountExternalIds[accountId] = fresh;
  } else {
    prefs.defaultExternalId = fresh;
  }
  writeConnectionPrefs(prefs);
  return fresh;
}

/**
 * Loads only REAL (non-demo) scan results from sessionStorage.
 * Explicitly rejects any fixture flagged `is_demo: true` so demo data never mixes with real scans.
 */
export function loadRealScanSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (
      parsed &&
      parsed.scanResults &&
      parsed.scanResults.resources &&
      parsed.scanResults.is_demo !== true
    ) {
      return parsed;
    }
  } catch {
    // Ignore parse errors
  }
  return null;
}

export function saveRealScanSession(data) {
  try {
    if (
      data &&
      data.scanResults &&
      data.scanResults.resources &&
      data.scanResults.is_demo !== true
    ) {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(data));
    } else {
      sessionStorage.removeItem(SESSION_KEY);
    }
  } catch {
    // Ignore storage errors
  }
}

export function clearScanSessionStorage() {
  try {
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(LEGACY_EXTERNAL_ID_KEY);
  } catch {
    // Ignore storage errors
  }
}

export function clearConnectionPreferencesStorage() {
  try {
    localStorage.removeItem(CONNECTION_PREFS_KEY);
    sessionStorage.removeItem(LEGACY_EXTERNAL_ID_KEY);
  } catch {
    // Ignore storage errors
  }
}

export function clearAllBrowserData() {
  clearScanSessionStorage();
  clearConnectionPreferencesStorage();
}
