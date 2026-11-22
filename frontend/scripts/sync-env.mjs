import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const FRONTEND_DIR = path.resolve(__dirname, "..");
export const ENV_FILE_PATH = path.join(FRONTEND_DIR, ".env");
const INFRA_DIR = path.resolve(FRONTEND_DIR, "..", "infra");

const AWS_REGION = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1";
const API_NAME = "aws-clarity-api";
const API_STAGE = "prod";

function runCmd(bin, args, timeoutMs = 8000) {
  try {
    return execFileSync(bin, args, {
      encoding: "utf8",
      timeout: timeoutMs,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return "";
  }
}

export function readExistingEnv() {
  const result = { apiUrl: "", accountId: "" };
  try {
    const raw = fs.readFileSync(ENV_FILE_PATH, "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim();
      if (key === "VITE_API_URL") result.apiUrl = val.replace(/\/+$/, "");
      if (key === "VITE_APP_ACCOUNT_ID") result.accountId = val;
    }
  } catch {
    // .env may not exist yet
  }
  return result;
}

export function discoverLiveBackend() {
  let apiUrl = "";
  let accountId = "";

  // 1. Primary source of truth: live AWS API Gateway (always reflects GitHub Actions / CI deploys too)
  const apisJson = runCmd("aws", [
    "apigateway",
    "get-rest-apis",
    "--region",
    AWS_REGION,
    "--output",
    "json",
  ]);
  if (apisJson) {
    try {
      const parsed = JSON.parse(apisJson);
      const matching = (parsed.items || [])
        .filter((item) => item?.name === API_NAME && item?.id)
        .sort((a, b) => new Date(b.createdDate || 0) - new Date(a.createdDate || 0));
      if (matching.length > 0) {
        apiUrl = `https://${matching[0].id}.execute-api.${AWS_REGION}.amazonaws.com/${API_STAGE}`;
      }
    } catch {
      // Ignore malformed output
    }
  }

  const acct = runCmd("aws", [
    "sts",
    "get-caller-identity",
    "--region",
    AWS_REGION,
    "--query",
    "Account",
    "--output",
    "text",
  ]);
  if (/^\d{12}$/.test(acct)) {
    accountId = acct;
  }

  // 2. Fallback: Terraform outputs (if AWS CLI wasn't available or didn't return an API)
  if (!apiUrl) {
    const tfUrl = runCmd("terraform", [`-chdir=${INFRA_DIR}`, "output", "-raw", "api_gateway_url"]);
    if (/^https:\/\/.+\.execute-api\..+\.amazonaws\.com\/.+/.test(tfUrl)) {
      apiUrl = tfUrl.replace(/\/+$/, "");
    }
  }
  if (!accountId) {
    const tfAcct = runCmd("terraform", [`-chdir=${INFRA_DIR}`, "output", "-raw", "app_account_id"]);
    if (/^\d{12}$/.test(tfAcct)) {
      accountId = tfAcct;
    }
  }

  return { apiUrl, accountId };
}

export function writeEnvIfChanged(apiUrl, accountId) {
  const existing = readExistingEnv();
  const nextUrl = (apiUrl || existing.apiUrl || "").replace(/\/+$/, "");
  const nextAcct = accountId || existing.accountId || "";
  if (!nextUrl) return { updated: false, apiUrl: existing.apiUrl, accountId: existing.accountId };

  const content = `VITE_API_URL=${nextUrl}\nVITE_APP_ACCOUNT_ID=${nextAcct}\n`;
  const changed = nextUrl !== existing.apiUrl || nextAcct !== existing.accountId || !fs.existsSync(ENV_FILE_PATH);
  if (changed) {
    fs.writeFileSync(ENV_FILE_PATH, content, "utf8");
  }
  return { updated: changed, apiUrl: nextUrl, accountId: nextAcct };
}

// Run directly when executed via `node scripts/sync-env.mjs` / `npm run predev`
const isDirectRun =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  const existing = readExistingEnv();
  const discovered = discoverLiveBackend();
  if (discovered.apiUrl) {
    const { updated, apiUrl } = writeEnvIfChanged(discovered.apiUrl, discovered.accountId);
    if (updated) {
      console.log(`[aws-clarity] Synced frontend/.env -> ${apiUrl}`);
    } else {
      console.log(`[aws-clarity] frontend/.env is up to date (${apiUrl})`);
    }
  } else if (existing.apiUrl) {
    console.warn(`[aws-clarity] Could not query live AWS API Gateway; keeping existing ${existing.apiUrl}`);
  } else {
    console.warn("[aws-clarity] No live AWS Clarity API Gateway found and frontend/.env is empty.");
  }
}
