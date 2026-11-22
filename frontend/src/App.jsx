import { useState, useEffect, useRef } from "react";
import SetupScreen from "./pages/SetupScreen";
import DashboardScreen from "./pages/DashboardScreen";
import { scanAccount } from "./services/api";
import { buildDemoScanData } from "./data/demoScanData";
import {
  clearAllBrowserData,
  clearConnectionPreferencesStorage,
  clearScanSessionStorage,
  getRememberedRoleArn,
  getStableExternalId,
  loadRealScanSession,
  saveConnectionDetails,
  saveRealScanSession,
} from "./utils/connectionStorage";

function App() {
  const initialSession = loadRealScanSession();

  // Always start on the landing & account connection screen (never bypass straight to dashboard)
  const [view, setView] = useState("setup");
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [scanResults, setScanResults] = useState(() => initialSession?.scanResults || null);
  const [previousScanResults, setPreviousScanResults] = useState(
    () => initialSession?.previousScanResults || null
  );
  const [isLoading, setIsLoading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanStatus, setScanStatus] = useState("");
  const [scanProgress, setScanProgress] = useState(null);
  const [storedRoleArn, setStoredRoleArn] = useState(
    () => initialSession?.storedRoleArn || getRememberedRoleArn()
  );
  const [storedExternalId, setStoredExternalId] = useState(() =>
    initialSession?.storedExternalId || getStableExternalId(initialSession?.storedRoleArn || getRememberedRoleArn())
  );
  const [connectionResetSeq, setConnectionResetSeq] = useState(0);

  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const feedbackRef = useRef(null);

  // Persist ONLY real (non-demo) scan results in sessionStorage
  useEffect(() => {
    if (!isDemoMode && scanResults && scanResults.resources && scanResults.is_demo !== true) {
      saveRealScanSession({
        scanResults,
        previousScanResults:
          previousScanResults && previousScanResults.is_demo !== true ? previousScanResults : null,
        storedRoleArn,
        storedExternalId,
      });
    }
  }, [isDemoMode, scanResults, previousScanResults, storedRoleArn, storedExternalId]);

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

  const handleExploreDemo = () => {
    setIsDemoMode(true);
    setIsLoading(false);
    setScanError("");
    setScanStatus("");
    setScanProgress(null);
    setView("dashboard");
  };

  const handleExitDemo = () => {
    setIsDemoMode(false);
    setView("setup");
  };

  const handleScanStart = async (roleArn, externalId) => {
    setIsDemoMode(false);
    if (scanResults && scanResults.resources && scanResults.is_demo !== true) {
      setPreviousScanResults(scanResults);
    }
    const resolvedExternalId = externalId?.trim() || getStableExternalId(roleArn);
    saveConnectionDetails(roleArn, resolvedExternalId);

    setIsLoading(true);
    setScanStatus("STARTING");
    setScanProgress(null);
    setScanError("");
    setScanResults(null);
    setStoredRoleArn(roleArn);
    setStoredExternalId(resolvedExternalId);
    setView("dashboard");

    try {
      // Always scan ALL enabled AWS regions for complete account inventory
      const results = await scanAccount(
        roleArn,
        "all",
        (status, progress) => {
          setScanStatus(status);
          if (progress) setScanProgress(progress);
        },
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
    setIsDemoMode(false);
    setScanError("");
    setScanStatus("");
    setScanProgress(null);
    setView("setup");
  };

  const handleClearCurrentResults = () => {
    setIsDemoMode(false);
    setScanResults(null);
    setPreviousScanResults(null);
    setScanError("");
    setScanStatus("");
    setScanProgress(null);
    clearScanSessionStorage();
    setView("setup");
  };

  const handleClearScanHistory = () => {
    setPreviousScanResults(null);
    clearScanSessionStorage();
    if (!isDemoMode && scanResults && scanResults.is_demo !== true) {
      saveRealScanSession({
        scanResults,
        previousScanResults: null,
        storedRoleArn,
        storedExternalId,
      });
    }
  };

  const handleForgetConnectionDetails = () => {
    clearConnectionPreferencesStorage();
    const freshId = getStableExternalId("");
    setStoredRoleArn("");
    setStoredExternalId(freshId);
    setConnectionResetSeq((n) => n + 1);
  };

  const handleClearAllLocalData = () => {
    clearAllBrowserData();
    const freshId = getStableExternalId("");
    setIsDemoMode(false);
    setScanResults(null);
    setPreviousScanResults(null);
    setScanError("");
    setScanStatus("");
    setScanProgress(null);
    setStoredRoleArn("");
    setStoredExternalId(freshId);
    setConnectionResetSeq((n) => n + 1);
    setView("setup");
  };

  const dataControls = {
    hasCurrentScan: Boolean(!isDemoMode && scanResults && scanResults.is_demo !== true),
    hasHistory: Boolean(!isDemoMode && previousScanResults && previousScanResults.is_demo !== true),
    hasConnectionDetails: Boolean(storedRoleArn),
    onClearCurrentResults: handleClearCurrentResults,
    onClearScanHistory: handleClearScanHistory,
    onForgetConnectionDetails: handleForgetConnectionDetails,
    onClearAllLocalData: handleClearAllLocalData,
  };

  const handleRescan = () => {
    if (isDemoMode) {
      handleExitDemo();
      return;
    }
    if (storedRoleArn) {
      handleScanStart(storedRoleArn, storedExternalId);
    } else {
      handleDisconnect();
    }
  };

  const activeDashboardResults = isDemoMode ? buildDemoScanData() : scanResults;
  const activePreviousResults = isDemoMode ? null : previousScanResults;
  const hasResumableRealScan = Boolean(scanResults && scanResults.is_demo !== true);

  return (
    <>
      {view === "setup" ? (
        <SetupScreen
          onScanStart={handleScanStart}
          onExploreDemo={handleExploreDemo}
          onResumeSession={
            hasResumableRealScan
              ? () => {
                  setIsDemoMode(false);
                  setView("dashboard");
                }
              : null
          }
          resumableAccountId={hasResumableRealScan ? scanResults?.account_id || "" : ""}
          initialRoleArn={storedRoleArn}
          initialExternalId={storedExternalId}
          connectionResetSeq={connectionResetSeq}
          scanError={scanError}
          setScanError={setScanError}
          dataControls={dataControls}
        />
      ) : (
        <DashboardScreen
          scanResults={activeDashboardResults}
          previousScanResults={activePreviousResults}
          isDemoMode={isDemoMode}
          onExitDemo={handleExitDemo}
          onRescan={handleRescan}
          onDisconnect={handleDisconnect}
          isLoading={isDemoMode ? false : isLoading}
          scanStatus={scanStatus}
          scanProgress={scanProgress}
          scanError={isDemoMode ? "" : scanError}
          dataControls={dataControls}
        />
      )}

      {/* Global floating feedback button */}
      <div
        ref={feedbackRef}
        className="fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-40 flex flex-col items-end"
      >
        {feedbackOpen && (
          <div className="mb-2.5 w-52 max-w-[calc(100vw-2rem)] bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
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
