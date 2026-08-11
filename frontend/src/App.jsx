import { useState, useEffect, useRef } from "react";
import SetupScreen from "./pages/SetupScreen";
import DashboardScreen from "./pages/DashboardScreen";
import { scanAccount } from "./services/api";

function App() {
  const [view, setView] = useState("setup");
  const [scanResults, setScanResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanStatus, setScanStatus] = useState("");
  const [storedRoleArn, setStoredRoleArn] = useState("");
  const [storedRegions, setStoredRegions] = useState(["us-east-1"]);

  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const feedbackRef = useRef(null);

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

  const handleScanStart = async (roleArn, regions) => {
    setIsLoading(true);
    setScanStatus("STARTING");
    setScanError("");
    setScanResults(null);
    setStoredRoleArn(roleArn);
    setStoredRegions(regions);
    setView("dashboard");
    try {
      const results = await scanAccount(roleArn, regions, (status) => setScanStatus(status));
      setScanResults(results);
    } catch (err) {
      setScanError(err.message || "An unexpected error occurred.");
      // Stay on dashboard — error rendered inline
    } finally {
      setIsLoading(false);
    }
  };

  const handleRescan = () => {
    setScanResults(null);
    setScanError("");
    setView("setup");
  };

  return (
    <>
      {view === "setup" ? (
        <SetupScreen
          onScanStart={handleScanStart}
          scanError={scanError}
          setScanError={setScanError}
        />
      ) : (
        <DashboardScreen
          scanResults={scanResults}
          onRescan={handleRescan}
          isLoading={isLoading}
          scanStatus={scanStatus}
          scanError={scanError}
          storedRoleArn={storedRoleArn}
          storedRegions={storedRegions}
          onStoredRegionsChange={setStoredRegions}
          onResultsChange={setScanResults}
        />
      )}

      {/* Global floating feedback button — fixed, persists across all views */}
      <div ref={feedbackRef} className="fixed bottom-6 right-6 z-50">

        {/* Popover — appears above the button */}
        {feedbackOpen && (
          <div className="mb-3 w-52 bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-800">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Send Feedback</p>
            </div>
            <div className="p-1">
              <a
                href="https://github.com/DavidDanso/aws-clarity/issues/new?template=bug_report.md&title=[Bug]"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setFeedbackOpen(false)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-gray-800 transition-colors group"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-red-400 shrink-0">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <div>
                  <p className="text-xs font-medium text-gray-200 group-hover:text-white">Report a Bug</p>
                  <p className="text-xs text-gray-500">Open a GitHub issue</p>
                </div>
              </a>
              <a
                href="https://github.com/DavidDanso/aws-clarity/issues/new?template=feature_request.md&title=[Feature]"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setFeedbackOpen(false)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-gray-800 transition-colors group"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-teal-400 shrink-0">
                  <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                </svg>
                <div>
                  <p className="text-xs font-medium text-gray-200 group-hover:text-white">Request a Feature</p>
                  <p className="text-xs text-gray-500">Share an idea</p>
                </div>
              </a>
            </div>
          </div>
        )}

        {/* Trigger button */}
        <button
          onClick={() => setFeedbackOpen(prev => !prev)}
          className={`flex items-center gap-2 text-xs font-medium px-3.5 py-2 rounded-full border shadow-lg transition-all duration-200 cursor-pointer ${
            feedbackOpen
              ? "bg-gray-800 border-gray-600 text-gray-200"
              : "bg-gray-900 border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 hover:bg-gray-800"
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
