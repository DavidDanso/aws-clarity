import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import {
  discoverLiveBackend,
  readExistingEnv,
  writeEnvIfChanged,
} from "./scripts/sync-env.mjs";

const DEV_PROXY_PREFIX = "/__aws_clarity_api";

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function awsClarityLiveApiProxy() {
  let activeApiUrl = readExistingEnv().apiUrl;
  let activeAccountId = readExistingEnv().accountId;

  const refreshLiveBackend = () => {
    const discovered = discoverLiveBackend();
    if (discovered.apiUrl) {
      activeApiUrl = discovered.apiUrl;
    }
    if (discovered.accountId) {
      activeAccountId = discovered.accountId;
    }
    return discovered;
  };

  return {
    name: "aws-clarity-live-api-proxy",
    configureServer(server) {
      server.middlewares.use(DEV_PROXY_PREFIX, async (req, res) => {
        const subPath = req.url || "/";
        const method = req.method || "GET";
        const bodyBuf =
          method !== "GET" && method !== "HEAD" ? await readRequestBody(req) : undefined;

        const forwardHeaders = {};
        if (req.headers["content-type"]) {
          forwardHeaders["Content-Type"] = req.headers["content-type"];
        }
        if (req.headers["x-scan-token"]) {
          forwardHeaders["X-Scan-Token"] = req.headers["x-scan-token"];
        }

        const forwardOnce = async (baseUrl) => {
          const targetUrl = `${baseUrl.replace(/\/+$/, "")}${subPath}`;
          return await fetch(targetUrl, {
            method,
            headers: forwardHeaders,
            body: bodyBuf && bodyBuf.length > 0 ? bodyBuf : undefined,
          });
        };

        if (!activeApiUrl) {
          refreshLiveBackend();
        }

        let upstreamRes = null;
        let lastError = null;
        let healedUrl = null;

        if (activeApiUrl) {
          try {
            upstreamRes = await forwardOnce(activeApiUrl);
            // If API Gateway was destroyed/recreated, an old URL fails DNS or returns 403/404.
            if (upstreamRes.status === 403 || upstreamRes.status === 404) {
              const previous = activeApiUrl;
              const discovered = refreshLiveBackend();
              if (discovered.apiUrl && discovered.apiUrl !== previous) {
                healedUrl = discovered.apiUrl;
                upstreamRes = await forwardOnce(healedUrl);
              }
            }
          } catch (err) {
            lastError = err;
            // Self-heal: re-discover live API Gateway URL (e.g. after GitHub Actions / Terraform redeploy)
            const previous = activeApiUrl;
            const discovered = refreshLiveBackend();
            if (discovered.apiUrl && discovered.apiUrl !== previous) {
              healedUrl = discovered.apiUrl;
              try {
                upstreamRes = await forwardOnce(healedUrl);
                lastError = null;
              } catch (retryErr) {
                lastError = retryErr;
              }
            }
          }
        }

        if (!upstreamRes) {
          res.statusCode = 503;
          res.setHeader("Content-Type", "application/json");
          res.end(
            JSON.stringify({
              status: "error",
              error_code: "BACKEND_NOT_DEPLOYED",
              message: activeApiUrl
                ? `Could not reach AWS Clarity backend (${activeApiUrl}). If the stack was destroyed or redeployed, run ./rebuild.sh or the GitHub Actions deploy workflow.`
                : "No live AWS Clarity API Gateway ('aws-clarity-api') was found in AWS. Deploy the backend via ./rebuild.sh or GitHub Actions, then retry.",
              detail: lastError ? String(lastError.message || lastError) : undefined,
            })
          );
          return;
        }

        const responseText = await upstreamRes.text();
        res.statusCode = upstreamRes.status;
        res.setHeader(
          "Content-Type",
          upstreamRes.headers.get("content-type") || "application/json"
        );
        res.end(responseText);

        // Persist the newly discovered URL to frontend/.env after the response finishes
        if (healedUrl) {
          console.log(`[aws-clarity] Auto-healed stale API Gateway URL -> ${healedUrl}`);
          setTimeout(() => {
            writeEnvIfChanged(healedUrl, activeAccountId);
          }, 150);
        }
      });
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), awsClarityLiveApiProxy()],
});
