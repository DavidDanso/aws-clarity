import { useState } from "react";
import SetupScreen from "./pages/SetupScreen";
import DashboardScreen from "./pages/DashboardScreen";
import { scanAccount } from "./services/api";

function App() {
  const [view, setView] = useState("setup");
  const [scanResults, setScanResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [scanError, setScanError] = useState("");

  const handleScanStart = async (roleArn) => {
    setIsLoading(true);
    setScanError("");
    setScanResults(null);
    setView("dashboard");
    try {
      const results = await scanAccount(roleArn);
      setScanResults(results);
    } catch (err) {
      setScanError(err.message || "An unexpected error occurred.");
      setView("setup");
    } finally {
      setIsLoading(false);
    }
  };

  const handleRescan = () => {
    setScanResults(null);
    setScanError("");
    setView("setup");
  };

  if (view === "setup") {
    return (
      <SetupScreen
        onScanStart={handleScanStart}
        scanError={scanError}
        setScanError={setScanError}
      />
    );
  }

  return (
    <DashboardScreen
      scanResults={scanResults}
      onRescan={handleRescan}
      isLoading={isLoading}
    />
  );
}

export default App;

