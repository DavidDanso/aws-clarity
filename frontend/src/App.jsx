import { useState } from "react";
import SetupScreen from "./pages/SetupScreen";

function App() {
  const [view, setView] = useState("setup");
  const [scanResults, setScanResults] = useState(null);

  const handleScanComplete = (results) => {
    setScanResults(results);
    setView("dashboard");
  };

  if (view === "setup") {
    return <SetupScreen onScanComplete={handleScanComplete} />;
  }

  // Dashboard placeholder — Milestone 7
  return (
    <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-2xl font-bold mb-4">Scan Complete</h1>
        <p className="text-slate-400 mb-4">
          {scanResults?.summary?.total_resources} resources scanned.
          Check the browser console for full results.
        </p>
        <button
          onClick={() => {
            setView("setup");
            setScanResults(null);
          }}
          className="px-6 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors cursor-pointer"
        >
          Scan Again
        </button>
      </div>
    </div>
  );
}

export default App;
