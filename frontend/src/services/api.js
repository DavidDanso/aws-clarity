const API_URL = import.meta.env.VITE_API_URL;

export const ERROR_MESSAGES = {
  INVALID_ROLE_ARN: "The Role ARN format is invalid. Expected: arn:aws:iam::123456789012:role/RoleName",
  ASSUME_ROLE_FAILED: "Could not assume the provided role. Verify the trust policy, App Account ID, and External ID.",
  PERMISSION_DENIED: "The role was assumed but lacks required read permissions.",
  UNAUTHORIZED_SCAN_ACCESS: "Scan access token was rejected. Please start a fresh scan.",
  INTERNAL_ERROR: "An unexpected error occurred on the server. Please try again.",
  NETWORK_ERROR: "Unable to reach the server. Check your internet connection and try again.",
  NO_REGIONS_SELECTED: "Please choose 'all' enabled regions or select at least one AWS region.",
  TIMEOUT: "The scan took longer than expected to respond. Please try again.",
};

const FAST_POLL_INTERVAL_MS = 400;
const MEDIUM_POLL_INTERVAL_MS = 800;
const SLOW_POLL_INTERVAL_MS = 1500;
const MAX_POLL_ATTEMPTS = 85; // ~90s total ceiling with fast 400ms initial polling

async function parseJsonSafe(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

export async function startScan(roleArn, regions = "all", externalId = "") {
  let response;
  try {
    response = await fetch(`${API_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        role_arn: roleArn,
        regions,
        ...(externalId ? { external_id: externalId } : {}),
      }),
    });
  } catch {
    const err = new Error(ERROR_MESSAGES.NETWORK_ERROR);
    err.code = "NETWORK_ERROR";
    throw err;
  }

  const data = await parseJsonSafe(response);
  if (!response.ok || data.status === "error") {
    const error = new Error(
      data.message || ERROR_MESSAGES[data.error_code] || ERROR_MESSAGES.INTERNAL_ERROR
    );
    error.code = data.error_code || "UNKNOWN_ERROR";
    throw error;
  }

  return { scanId: data.scan_id, scanToken: data.scan_token };
}

export async function pollScanStatus(scanId, scanToken, onProgress) {
  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
    let response;
    try {
      response = await fetch(`${API_URL}/scan/${encodeURIComponent(scanId)}/status`, {
        headers: scanToken ? { "X-Scan-Token": scanToken } : {},
      });
    } catch {
      const err = new Error(ERROR_MESSAGES.NETWORK_ERROR);
      err.code = "NETWORK_ERROR";
      throw err;
    }

    const data = await parseJsonSafe(response);
    if (!response.ok) {
      const error = new Error(
        data.message || ERROR_MESSAGES[data.error_code] || "Failed to fetch scan status."
      );
      error.code = data.error_code || "STATUS_ERROR";
      throw error;
    }

    const state = data.scan_state || data.status;
    if (typeof onProgress === "function") {
      onProgress(state, data.progress || null);
    }

    if (state === "COMPLETE" || state === "INCOMPLETE") {
      return data;
    }

    if (state === "FAILED") {
      const error = new Error(
        data.message || ERROR_MESSAGES[data.error_code] || ERROR_MESSAGES.INTERNAL_ERROR
      );
      error.code = data.error_code || "UNKNOWN_ERROR";
      throw error;
    }

    const delayMs =
      attempt < 20
        ? FAST_POLL_INTERVAL_MS
        : attempt < 40
        ? MEDIUM_POLL_INTERVAL_MS
        : SLOW_POLL_INTERVAL_MS;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }

  throw new Error(ERROR_MESSAGES.TIMEOUT);
}

export async function scanAccount(roleArn, regions = "all", onProgress, externalId = "") {
  const { scanId, scanToken } = await startScan(roleArn, regions, externalId);
  return await pollScanStatus(scanId, scanToken, onProgress);
}

export async function checkPermissions(roleArn, externalId = "") {
  let response;
  try {
    response = await fetch(`${API_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        role_arn: roleArn,
        action: "precheck",
        ...(externalId ? { external_id: externalId } : {}),
      }),
    });
  } catch {
    const err = new Error(ERROR_MESSAGES.NETWORK_ERROR);
    err.code = "NETWORK_ERROR";
    throw err;
  }

  const data = await parseJsonSafe(response);
  if (!response.ok || data.status === "error") {
    const error = new Error(
      data.message || ERROR_MESSAGES[data.error_code] || "Account verification failed."
    );
    error.code = data.error_code || "UNKNOWN_ERROR";
    throw error;
  }

  return data;
}
