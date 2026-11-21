const ROLE_ARN_REGEX = /^arn:aws:iam::\d{12}:role\/([\w+=,.@-]+\/)*[\w+=,.@-]+$/;
const EXTERNAL_ID_REGEX = /^[A-Za-z0-9+=,.@:/_-]{2,128}$/;

export function validateRoleArn(arn) {
  return typeof arn === "string" && ROLE_ARN_REGEX.test(arn.trim());
}

export function validateExternalId(externalId) {
  if (!externalId || !String(externalId).trim()) return true;
  return EXTERNAL_ID_REGEX.test(String(externalId).trim());
}

export function generateExternalId() {
  const bytes = new Uint8Array(8);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `aws-clarity-${hex}`;
}

export function maskAccountId(accountId) {
  if (!accountId || accountId.length < 4) return "****";
  return "****" + accountId.slice(-4);
}

export function formatTimestamp(isoString) {
  if (!isoString) return "";
  const date = new Date(isoString);
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
}
