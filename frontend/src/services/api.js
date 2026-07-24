const API_URL = import.meta.env.VITE_API_URL;

export const ERROR_MESSAGES = {
  INVALID_ROLE_ARN: "The Role ARN format is invalid. Expected: arn:aws:iam::123456789012:role/RoleName",
  ASSUME_ROLE_FAILED: "Could not assume the provided role. Verify the trust policy is correctly configured.",
  PERMISSION_DENIED: "The role was assumed but lacks required read permissions.",
  INTERNAL_ERROR: "An unexpected error occurred on the server. Please try again.",
  NETWORK_ERROR: "Unable to reach the server. Check your internet connection and try again.",
  NO_REGIONS_SELECTED: "Please select at least one region to scan.",
  INVALID_REGION: "One or more selected regions are not supported.",
};

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_ATTEMPTS = 45; // 45 * 2s = 90s ceiling, well past typical scan time

export async function startScan(roleArn, regions = ["us-east-1"]) {
  const response = await fetch(`${API_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role_arn: roleArn, regions }),
  });

  const data = await response.json();
  if (!response.ok || data.status === "error") {
    const error = new Error(data.message || ERROR_MESSAGES.UNKNOWN || "Unknown error");
    error.code = data.error_code || "UNKNOWN_ERROR";
    throw error;
  }

  return data.scan_id;
}

export async function pollScanStatus(scanId, onProgress) {
  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
    const response = await fetch(`${API_URL}/scan/${scanId}/status`);
    const data = await response.json();

    if (!response.ok) {
      throw new Error("Failed to fetch scan status");
    }

    if (typeof onProgress === "function") {
      onProgress(data.status); // Inform the UI
    }

    if (data.status === "COMPLETE") {
      return data; // The full payload is already flat — no nested "result" key
    }

    if (data.status === "FAILED") {
      const error = new Error(data.message || "Unknown error");
      error.code = data.error_code || "UNKNOWN_ERROR";
      throw error;
    }

    // If PENDING or RUNNING, wait and try again
    await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  throw new Error(ERROR_MESSAGES.TIMEOUT || "The scan timed out");
}

// Keep this wrapper signature the same so the UI doesn't break,
// but add the new onProgress callback
export async function scanAccount(roleArn, regions = ["us-east-1"], onProgress) {
  const scanId = await startScan(roleArn, regions);
  return await pollScanStatus(scanId, onProgress);
}
