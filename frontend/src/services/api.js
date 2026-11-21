const API_URL = import.meta.env.VITE_API_URL;

export const ERROR_MESSAGES = {
  INVALID_ROLE_ARN: "The Role ARN format is invalid. Expected: arn:aws:iam::123456789012:role/RoleName",
  ASSUME_ROLE_FAILED: "Could not assume the provided role. Verify the trust policy, App Account ID, and External ID.",
  PERMISSION_DENIED: "The role was assumed but lacks required read permissions.",
  INTERNAL_ERROR: "An unexpected error occurred on the server. Please try again.",
  NETWORK_ERROR: "Unable to reach the server. Check your internet connection and try again.",
  NO_REGIONS_SELECTED: "Please select at least one region to scan.",
  INVALID_REGION: "One or more selected regions are not supported.",
  TIMEOUT: "The scan took longer than expected to respond. Try scanning a single region or re-running the scan.",
};

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_ATTEMPTS = 50; // 50 * 2s = 100s ceiling

async function parseJsonSafe(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

export async function startScan(roleArn, regions = ["us-east-1"], externalId = "") {
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

  return data.scan_id;
}

export async function pollScanStatus(scanId, onProgress) {
  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
    let response;
    try {
      response = await fetch(`${API_URL}/scan/${encodeURIComponent(scanId)}/status`);
    } catch {
      const err = new Error(ERROR_MESSAGES.NETWORK_ERROR);
      err.code = "NETWORK_ERROR";
      throw err;
    }

    const data = await parseJsonSafe(response);
    if (!response.ok) {
      throw new Error(data.message || "Failed to fetch scan status.");
    }

    if (typeof onProgress === "function") {
      onProgress(data.status);
    }

    if (data.status === "COMPLETE") {
      return data;
    }

    if (data.status === "FAILED") {
      const error = new Error(
        data.message || ERROR_MESSAGES[data.error_code] || ERROR_MESSAGES.INTERNAL_ERROR
      );
      error.code = data.error_code || "UNKNOWN_ERROR";
      throw error;
    }

    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  throw new Error(ERROR_MESSAGES.TIMEOUT);
}

export async function scanAccount(roleArn, regions = ["us-east-1"], onProgress, externalId = "") {
  const scanId = await startScan(roleArn, regions, externalId);
  return await pollScanStatus(scanId, onProgress);
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
      data.message || ERROR_MESSAGES[data.error_code] || "Permission pre-check failed."
    );
    error.code = data.error_code || "UNKNOWN_ERROR";
    throw error;
  }

  return data;
}
