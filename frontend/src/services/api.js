const API_URL = import.meta.env.VITE_API_URL;

export const ERROR_MESSAGES = {
  INVALID_ROLE_ARN: "The Role ARN format is invalid. Expected: arn:aws:iam::123456789012:role/RoleName",
  ASSUME_ROLE_FAILED: "Could not assume the provided role. Verify the trust policy is correctly configured.",
  PERMISSION_DENIED: "The role was assumed but lacks required read permissions.",
  INTERNAL_ERROR: "An unexpected error occurred on the server. Please try again.",
  NETWORK_ERROR: "Unable to reach the server. Check your internet connection and try again.",
};

export async function scanAccount(roleArn) {
  try {
    const response = await fetch(`${API_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_arn: roleArn }),
    });

    const data = await response.json();

    if (!response.ok || data.status === "error") {
      const error = new Error(data.message || "Scan failed");
      error.code = data.error_code || "UNKNOWN_ERROR";
      throw error;
    }

    return data;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(ERROR_MESSAGES.NETWORK_ERROR);
    }
    throw error;
  }
}
