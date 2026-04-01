import { useState } from "react";
import TopBar from "../components/TopBar";
import SummaryCards from "../components/SummaryCards";
import ResourceTable from "../components/ResourceTable";
import DetailDrawer from "../components/DetailDrawer";

export default function DashboardScreen({ scanResults, onRescan }) {
  const [selectedResource, setSelectedResource] = useState(null);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <TopBar
          accountId={scanResults.account_id}
          region={scanResults.region}
          scannedAt={scanResults.scanned_at}
          onRescan={onRescan}
        />

        <SummaryCards summary={scanResults.summary} />

        <ResourceTable
          resources={scanResults.resources}
          onInspect={(resource) => setSelectedResource(resource)}
        />
      </div>

      {selectedResource && (
        <DetailDrawer
          resource={selectedResource}
          onClose={() => setSelectedResource(null)}
        />
      )}
    </div>
  );
}
