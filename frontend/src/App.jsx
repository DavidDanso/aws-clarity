import { useState, useEffect, useRef } from "react";
import SetupScreen from "./pages/SetupScreen";
import DashboardScreen from "./pages/DashboardScreen";
import { buildDemoScanData } from "./data/demoScanData";
import { clearAllBrowserData } from "./utils/connectionStorage";

function App() {
  // Always start on the privacy-first landing & report import screen.
  // Imported customer reports stay strictly in-memory by default (zero server upload,
  // zero automatic persistence to localStorage/sessionStorage).
  const [view, setView] = useState("setup");
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [previousScanResults, setPreviousScanResults] = useState(null);
  const [importedFileName, setImportedFileName] = useState("");
  const [importError, setImportError] = useState("");

  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const feedbackRef = useRef(null);
  const feedbackButtonRef = useRef(null);

  // Update SPA document title on view transitions (modern-web-guidance: accessibility)
  useEffect(() => {
    if (view === "setup") {
      document.title = "AWS Clarity — Privacy-First, Local-Only AWS Assessment";
    } else if (isDemoMode) {
      document.title = "Demo Dashboard | AWS Clarity";
    } else {
      document.title = "Account Dashboard | AWS Clarity";
    }
  }, [view, isDemoMode]);

  useEffect(() => {
    if (!feedbackOpen) return;
    const handleClickOutside = (e) => {
      if (feedbackRef.current && !feedbackRef.current.contains(e.target)) {
        setFeedbackOpen(false);
      }
    };
    const handleEscape = (e) => {
      if (e.key === "Escape") {
        setFeedbackOpen(false);
        feedbackButtonRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [feedbackOpen]);

  const handleExploreDemo = () => {
    setIsDemoMode(true);
    setImportError("");
    setView("dashboard");
  };

  const handleExitDemo = () => {
    setIsDemoMode(false);
    setView("setup");
  };

  const handleImportReport = (report, fileName = "") => {
    setIsDemoMode(false);
    setImportError("");
    if (scanResults && scanResults.resources && scanResults.is_demo !== true) {
      setPreviousScanResults(scanResults);
    }
    setScanResults(report);
    setImportedFileName(fileName);
    setView("dashboard");
  };

  const handleReturnHome = () => {
    setIsDemoMode(false);
    setImportError("");
    setView("setup");
  };

  const handleClearCurrentReport = () => {
    setIsDemoMode(false);
    setScanResults(null);
    setPreviousScanResults(null);
    setImportedFileName("");
    setImportError("");
    setView("setup");
  };

  const handleClearDiffHistory = () => {
    setPreviousScanResults(null);
  };

  const handleClearAllLocalData = () => {
    clearAllBrowserData();
    setIsDemoMode(false);
    setScanResults(null);
    setPreviousScanResults(null);
    setImportedFileName("");
    setImportError("");
    setView("setup");
  };

  const dataControls = {
    hasCurrentReport: Boolean(!isDemoMode && scanResults && scanResults.is_demo !== true),
    hasDiffHistory: Boolean(!isDemoMode && previousScanResults && previousScanResults.is_demo !== true),
    onClearCurrentReport: handleClearCurrentReport,
    onClearDiffHistory: handleClearDiffHistory,
    onClearAllLocalData: handleClearAllLocalData,
  };

  const activeDashboardResults = isDemoMode ? buildDemoScanData() : scanResults;
  const activePreviousResults = isDemoMode ? null : previousScanResults;
  const hasResumableRealReport = Boolean(scanResults && scanResults.is_demo !== true);

  return (
    <>
      {view === "setup" ? (
        <SetupScreen
          onImportReport={handleImportReport}
          onExploreDemo={handleExploreDemo}
          onResumeReport={
            hasResumableRealReport
              ? () => {
                  setIsDemoMode(false);
                  setView("dashboard");
                }
              : null
          }
          resumableAccountId={hasResumableRealReport ? scanResults?.account_id || "" : ""}
          importError={importError}
          setImportError={setImportError}
          dataControls={dataControls}
        />
      ) : (
        <DashboardScreen
          scanResults={activeDashboardResults}
          previousScanResults={activePreviousResults}
          importedFileName={isDemoMode ? "" : importedFileName}
          isDemoMode={isDemoMode}
          onExitDemo={handleExitDemo}
          onImportNewerReport={handleImportReport}
          onReturnHome={handleReturnHome}
          dataControls={dataControls}
        />
      )}

      {/* Global floating feedback button */}
      <div
        ref={feedbackRef}
        className="fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-40 flex flex-col items-end"
      >
        {feedbackOpen && (
          <div
            id="feedback-menu"
            role="menu"
            aria-label="Feedback and security links"
            className="mb-2.5 w-56 max-w-[calc(100vw-2rem)] bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden"
          >
            <div className="px-3 py-2 border-b border-slate-800">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Feedback &amp; Security</p>
            </div>
            <div className="p-1">
              <a
                role="menuitem"
                href="https://github.com/DavidDanso/aws-clarity/issues/new?template=bug_report.md&title=[Bug]"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setFeedbackOpen(false)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors group"
              >
                <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-red-400 shrink-0">
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
                role="menuitem"
                href="https://github.com/DavidDanso/aws-clarity/issues/new?template=feature_request.md&title=[Feature]"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setFeedbackOpen(false)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors group"
              >
                <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-teal-400 shrink-0">
                  <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                </svg>
                <div>
                  <p className="text-xs font-medium text-slate-200 group-hover:text-white">Request a Feature</p>
                  <p className="text-xs text-slate-500">Share an idea</p>
                </div>
              </a>
              <a
                role="menuitem"
                href="https://github.com/DavidDanso/aws-clarity/security/advisories/new"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setFeedbackOpen(false)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-slate-800 transition-colors group"
              >
                <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-amber-400 shrink-0">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <div>
                  <p className="text-xs font-medium text-slate-200 group-hover:text-white">Report Security Issue</p>
                  <p className="text-xs text-slate-500">Private GitHub advisory</p>
                </div>
              </a>
            </div>
          </div>
        )}

        <button
          ref={feedbackButtonRef}
          type="button"
          aria-expanded={feedbackOpen}
          aria-haspopup="menu"
          aria-controls="feedback-menu"
          onClick={() => setFeedbackOpen((prev) => !prev)}
          className={`flex items-center gap-2 text-xs font-medium px-3.5 py-2 rounded-full border shadow-lg transition-colors duration-200 cursor-pointer ${
            feedbackOpen
              ? "bg-slate-800 border-slate-600 text-slate-200"
              : "bg-slate-900 border-slate-700 text-slate-300 hover:text-white hover:border-slate-600 hover:bg-slate-800"
          }`}
        >
          <svg aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="shrink-0">
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
          </svg>
          Feedback
        </button>
      </div>
    </>
  );
}

export default App;
