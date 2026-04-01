const ROLE_ARN_REGEX = /^arn:aws:iam::\d{12}:role\/[\w+=,.@-]+$/;

export function validateRoleArn(arn) {
  return ROLE_ARN_REGEX.test(arn);
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
