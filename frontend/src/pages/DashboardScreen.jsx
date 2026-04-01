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

        {scanResults.partial === true && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg border bg-amber-500/15 border-amber-500/30">
            <svg className="w-5 h-5 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
            <p className="text-sm text-amber-400">
              Scan completed partially due to timeout. Some resources may not be shown.
            </p>
          </div>
        )}

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
