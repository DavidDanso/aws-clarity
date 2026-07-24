import { useState } from "react";
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
      scanStatus={scanStatus}
      scanError={scanError}
      storedRoleArn={storedRoleArn}
      storedRegions={storedRegions}
      onStoredRegionsChange={setStoredRegions}
      onResultsChange={setScanResults}
    />
  );
}

export default App;

