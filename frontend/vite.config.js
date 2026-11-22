import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const PRODUCTION_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

/**
 * Injects a strict privacy-enforcing Content Security Policy into the production
 * static build (`dist/index.html`). `connect-src 'none'` enforces at the browser
 * level that the deployed static website cannot upload imported reports or send
 * analytics/telemetry to any server.
 */
function strictLocalFirstCsp() {
  let isBuild = false;
  return {
    name: "aws-clarity-strict-csp",
    configResolved(config) {
      isBuild = config.command === "build";
    },
    transformIndexHtml(html) {
      if (!isBuild) return html;
      const metaTag = `    <meta http-equiv="Content-Security-Policy" content="${PRODUCTION_CSP}" />\n`;
      return html.replace("<meta charset=\"UTF-8\" />\n", `<meta charset="UTF-8" />\n${metaTag}`);
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  base: "./",
  plugins: [react(), strictLocalFirstCsp()],
});
