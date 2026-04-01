import { useState } from "react";
import SetupScreen from "./pages/SetupScreen";
import DashboardScreen from "./pages/DashboardScreen";

function App() {
  const [view, setView] = useState("setup");
  const [scanResults, setScanResults] = useState(null);

  const handleScanComplete = (results) => {
    setScanResults(results);
    setView("dashboard");
  };

  const handleRescan = () => {
    setScanResults(null);
    setView("setup");
  };

  if (view === "setup") {
    return <SetupScreen onScanComplete={handleScanComplete} />;
  }

  return (
    <DashboardScreen
      scanResults={scanResults}
      onRescan={handleRescan}
    />
  );
}

export default App;
