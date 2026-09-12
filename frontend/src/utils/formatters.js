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

export const formatCost = (amount) => {
  if (amount === null || amount === undefined) return "—";
  if (amount === 0) return "$0.00";
  if (amount < 0.0001) return `$${amount.toFixed(6)}`;
  if (amount < 0.01) return `$${amount.toFixed(4)}`;
  if (amount < 1) return `$${amount.toFixed(3)}`;
  if (amount >= 1000) return `$${(amount / 1000).toFixed(2)}k`;
  return `$${amount.toFixed(2)}`;
};

