import { useState, useEffect, useRef } from "react";
import SetupScreen from "./pages/SetupScreen";
import DashboardScreen from "./pages/DashboardScreen";
import { scanAccount } from "./services/api";
import { DEFAULT_EXTERNAL_ID } from "./utils/constants";

const SESSION_KEY = "aws_clarity_session";

function loadSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && parsed.scanResults && parsed.scanResults.resources) {
      return parsed;
    }
  } catch {
    // Ignore parse errors and fall back
  }
  return null;
}

function saveSession(data) {
  try {
    if (data && data.scanResults && data.scanResults.resources) {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(data));
    } else {
      sessionStorage.removeItem(SESSION_KEY);
    }
  } catch {
    // Ignore storage quota or security errors
  }
}

function App() {
  const initialSession = loadSession();

  const [view, setView] = useState(() => (initialSession ? "dashboard" : "setup"));
  const [scanResults, setScanResults] = useState(() => initialSession?.scanResults || null);
  const [previousScanResults, setPreviousScanResults] = useState(() => initialSession?.previousScanResults || null);
  const [isLoading, setIsLoading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanStatus, setScanStatus] = useState("");
  const [storedRoleArn, setStoredRoleArn] = useState(() => initialSession?.storedRoleArn || "");
  const [storedExternalId, setStoredExternalId] = useState(
    () => initialSession?.storedExternalId || DEFAULT_EXTERNAL_ID
  );
  const [storedRegions, setStoredRegions] = useState(() => initialSession?.storedRegions || ["us-east-1"]);

  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const feedbackRef = useRef(null);

  useEffect(() => {
    if (scanResults && scanResults.resources) {
      saveSession({
        scanResults,
        previousScanResults,
        storedRoleArn,
        storedExternalId,
        storedRegions,
      });
    }
  }, [scanResults, previousScanResults, storedRoleArn, storedExternalId, storedRegions]);

  useEffect(() => {
    if (!feedbackOpen) return;
    const handleClickOutside = (e) => {
      if (feedbackRef.current && !feedbackRef.current.contains(e.target)) {
        setFeedbackOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [feedbackOpen]);

  const handleScanStart = async (roleArn, regions, externalId = DEFAULT_EXTERNAL_ID) => {
    if (scanResults && scanResults.resources) {
      setPreviousScanResults(scanResults);
    }
    const resolvedExternalId = externalId?.trim() || DEFAULT_EXTERNAL_ID;
    setIsLoading(true);
    setScanStatus("STARTING");
    setScanError("");
    setScanResults(null);
    setStoredRoleArn(roleArn);
    setStoredExternalId(resolvedExternalId);
    setStoredRegions(regions);
    setView("dashboard");

    try {
      const results = await scanAccount(
        roleArn,
        regions,
        (status) => setScanStatus(status),
        resolvedExternalId
      );
      setScanResults(results);
    } catch (err) {
      setScanError(err.message || "An unexpected error occurred.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisconnect = () => {
    setScanResults(null);
    setPreviousScanResults(null);
    setScanError("");
    setScanStatus("");
    sessionStorage.removeItem(SESSION_KEY);
    setView("setup");
  };

  const handleRescan = () => {
    if (storedRoleArn) {
      handleScanStart(storedRoleArn, storedRegions, storedExternalId);
    } else {
      handleDisconnect();
    }
  };

  return (
    <>
      {view === "setup" ? (
        <SetupScreen
          onScanStart={handleScanStart}
          initialRoleArn={storedRoleArn}
          initialExternalId={storedExternalId}
          initialRegion={storedRegions[0] || "us-east-1"}
          scanError={scanError}
          setScanError={setScanError}
        />
      ) : (
        <DashboardScreen
          scanResults={scanResults}
          previousScanResults={previousScanResults}
          onRescan={handleRescan}
          onDisconnect={handleDisconnect}
          isLoading={isLoading}
          scanStatus={scanStatus}
          scanError={scanError}
          storedRoleArn={storedRoleArn}
          storedExternalId={storedExternalId}
          storedRegions={storedRegions}
          onStoredRegionsChange={setStoredRegions}
          onResultsChange={(newResults) => {
            if (scanResults && scanResults.resources) {
              setPreviousScanResults(scanResults);
            }
            setScanResults(newResults);
          }}
        />
      )}

      {/* Global floating feedback button */}
      <div ref={feedbackRef} className="fixed bottom-6 right-6 z-40">
        {feedbackOpen && (
          <div className="mb-3 w-52 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
            <div className="px-3 py-2 border-b border-slate-800">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Send Feedback</p>
            </div>
            <div className="p-1">
              <a
                href="https://github.com/DavidDanso/aws-clarity/issues/new?template=bug_report.md&title=[Bug]"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setFeedbackOpen(false)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors group"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-red-400 shrink-0">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <div>
                  <p className="text-xs font-medium text-slate-200 group-hover:text-white">Report a Bug</p>
                  <p className="text-xs text-slate-500">Open a GitHub issue</p>
                </div>
              </a>
              <a
                href="https://github.com/DavidDanso/aws-clarity/issues/new?template=feature_request.md&title=[Feature]"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setFeedbackOpen(false)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors group"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-teal-400 shrink-0">
                  <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                </svg>
                <div>
                  <p className="text-xs font-medium text-slate-200 group-hover:text-white">Request a Feature</p>
                  <p className="text-xs text-slate-500">Share an idea</p>
                </div>
              </a>
            </div>
          </div>
        )}

        <button
          type="button"
          onClick={() => setFeedbackOpen((prev) => !prev)}
          className={`flex items-center gap-2 text-xs font-medium px-3.5 py-2 rounded-full border shadow-lg transition-all duration-200 cursor-pointer ${
            feedbackOpen
              ? "bg-slate-800 border-slate-600 text-slate-200"
              : "bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600 hover:bg-slate-800"
          }`}
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="shrink-0">
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
          </svg>
          Feedback
        </button>
      </div>
    </>
  );
}

export default App;
