import React from 'react';
import { ScanReport, CapabilitiesResponse } from '../types';
import { Monitor, Activity, Clock, ShieldCheck } from 'lucide-react';

interface SummaryCardsProps {
  report: ScanReport | null;
  isScanning: boolean;
  capabilities: CapabilitiesResponse | null;
}

export const SummaryCards: React.FC<SummaryCardsProps> = ({
  report,
  isScanning,
  capabilities,
}) => {
  const isAgentOnline = Boolean(capabilities?.external_agent_configured);
  const isVercel = capabilities?.deployment === 'vercel';

  // 1. Devices Discovered
  let devicesValue = 'No scan yet';
  let devicesDetail = 'Enter a target network below';
  if (isScanning) {
    devicesValue = 'Probing...';
    devicesDetail = 'Scanning network addresses';
  } else if (report) {
    const count = report.discoveredDevices.length;
    devicesValue = count === 1 ? '1 Device' : `${count} Devices`;
    devicesDetail = `out of ${report.totalHosts} ${report.totalHosts === 1 ? 'host' : 'hosts'} probed`;
  }

  // 2. Scan Status
  let statusValue = 'Ready';
  let statusColor = 'text-slate-300';

  if (isScanning) {
    statusValue = 'Scanning...';
    statusColor = 'text-rose-400 font-semibold';
  } else if (report) {
    if (report.status === 'completed') {
      statusValue = 'Completed';
      statusColor = 'text-emerald-400 font-semibold';
    } else if (report.status === 'partial') {
      statusValue = 'Partial';
      statusColor = 'text-amber-400 font-semibold';
    } else if (report.status === 'failed') {
      statusValue = 'Failed';
      statusColor = 'text-rose-400 font-semibold';
    }
  }

  // 3. Scan Duration
  let durationValue = '—';
  let durationDetail = 'Elapsed time';
  if (isScanning) {
    durationValue = 'Measuring...';
    durationDetail = 'Active scan running';
  } else if (report) {
    durationValue = `${report.durationSeconds.toFixed(2)}s`;
    durationDetail = `Method: ${report.scanMethod === 'arp_discovery' ? 'Layer 2 ARP' : 'Layer 3 TCP'}`;
  }

  // 4. Scanner Connection
  let connectionValue = isAgentOnline ? 'Agent Online' : isVercel ? 'Cloud Serverless' : 'Server Connected';
  let connectionDetail = isAgentOnline
    ? 'Layer 2 ARP enabled'
    : 'Layer 3 TCP connect enabled';
  let connectionDot = isAgentOnline ? 'bg-emerald-500' : 'bg-rose-500';

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Metric 1: Discovered Devices */}
      <div className="bg-[#0f1523] border border-slate-800/80 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-xs font-medium">Discovered Devices</span>
          <Monitor className="w-4 h-4 text-slate-500" />
        </div>
        <div className="text-xl font-bold text-white font-mono tracking-tight">
          {devicesValue}
        </div>
        <div className="text-xs text-slate-400 mt-0.5 truncate">
          {devicesDetail}
        </div>
      </div>

      {/* Metric 2: Scan Status */}
      <div className="bg-[#0f1523] border border-slate-800/80 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-xs font-medium">Scan Status</span>
          <Activity className="w-4 h-4 text-slate-500" />
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-xl font-bold tracking-tight ${statusColor}`}>
            {statusValue}
          </span>
        </div>
        <div className="text-xs text-slate-400 mt-0.5 truncate">
          {report ? `Target: ${report.targetNetwork}` : 'Awaiting user input'}
        </div>
      </div>

      {/* Metric 3: Scan Duration */}
      <div className="bg-[#0f1523] border border-slate-800/80 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-xs font-medium">Scan Duration</span>
          <Clock className="w-4 h-4 text-slate-500" />
        </div>
        <div className="text-xl font-bold text-white font-mono tracking-tight">
          {durationValue}
        </div>
        <div className="text-xs text-slate-400 mt-0.5 truncate">
          {durationDetail}
        </div>
      </div>

      {/* Metric 4: Scanner Connection */}
      <div className="bg-[#0f1523] border border-slate-800/80 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-xs font-medium">Scanner Engine</span>
          <ShieldCheck className="w-4 h-4 text-slate-500" />
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full ${connectionDot} shrink-0`} />
          <span className="text-xl font-bold text-white tracking-tight truncate">
            {connectionValue}
          </span>
        </div>
        <div className="text-xs text-slate-400 mt-0.5 truncate">
          {connectionDetail}
        </div>
      </div>
    </div>
  );
};
