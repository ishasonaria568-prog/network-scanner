import React, { useState, useMemo } from 'react';
import { DiscoveredDevice, ScanReport } from '../types';
import {
  Search,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  FileSpreadsheet,
  FileCode,
  Copy,
  Check,
  Server,
  Download,
  AlertCircle,
} from 'lucide-react';

interface ResultsTableProps {
  report: ScanReport | null;
  onSelectDevice: (device: DiscoveredDevice) => void;
  onNavigateToScanner: () => void;
}

export const ResultsTable: React.FC<ResultsTableProps> = ({
  report,
  onSelectDevice,
  onNavigateToScanner,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<'ip' | 'hostname' | 'ports' | 'latency'>('ip');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [copied, setCopied] = useState(false);

  const devices = report?.discoveredDevices || [];

  // Filter & Sort
  const filteredDevices = useMemo(() => {
    let result = [...devices];

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (d) =>
          d.ipAddress.toLowerCase().includes(q) ||
          (d.macAddress && d.macAddress.toLowerCase().includes(q)) ||
          (d.hostname && d.hostname.toLowerCase().includes(q)) ||
          (d.vendor && d.vendor.toLowerCase().includes(q)) ||
          (d.osMatch && d.osMatch.toLowerCase().includes(q)) ||
          d.openPorts.some((p) => String(p).includes(q))
      );
    }

    result.sort((a, b) => {
      let comparison = 0;
      if (sortField === 'ip') {
        const toNum = (ip: string) =>
          ip
            .split('.')
            .map(Number)
            .reduce((acc, octet) => (acc << 8) + octet, 0) >>> 0;
        comparison = toNum(a.ipAddress) - toNum(b.ipAddress);
      } else if (sortField === 'hostname') {
        comparison = (a.hostname || '').localeCompare(b.hostname || '');
      } else if (sortField === 'ports') {
        comparison = a.openPorts.length - b.openPorts.length;
      } else if (sortField === 'latency') {
        const latA = a.latencyMs ?? 999999;
        const latB = b.latencyMs ?? 999999;
        comparison = latA - latB;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return result;
  }, [devices, searchQuery, sortField, sortOrder]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filteredDevices.length / pageSize));
  const paginatedDevices = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredDevices.slice(start, start + pageSize);
  }, [filteredDevices, currentPage, pageSize]);

  const handleSort = (field: 'ip' | 'hostname' | 'ports' | 'latency') => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const handleDownloadCsv = () => {
    if (!report) return;
    window.location.href = `/api/scans/${report.scanId}/export?format=csv`;
  };

  const handleDownloadJson = () => {
    if (!report) return;
    window.location.href = `/api/scans/${report.scanId}/export?format=json`;
  };

  const handleCopyJson = () => {
    if (!report) return;
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Informative Empty State before first scan
  if (!report) {
    return (
      <div className="bg-white border border-slate-200/90 rounded-xl p-12 text-center shadow-xs">
        <div className="w-12 h-12 bg-blue-50 border border-blue-200 rounded-full flex items-center justify-center mx-auto mb-4 text-blue-600">
          <Server className="w-6 h-6" />
        </div>
        <h3 className="text-base font-bold text-slate-900">No Scan Results Yet</h3>
        <p className="text-xs text-slate-600 mt-1.5 max-w-md mx-auto leading-relaxed">
          Configure a target network (such as <code className="bg-slate-100 px-1 py-0.5 rounded text-slate-800 font-mono">127.0.0.1/32</code> or <code className="bg-slate-100 px-1 py-0.5 rounded text-slate-800 font-mono">192.168.1.0/24</code>) in the Scanner tab to run your first discovery probe.
        </p>
        <button
          onClick={onNavigateToScanner}
          className="mt-5 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-xs transition-colors"
        >
          Go to Scanner
        </button>
      </div>
    );
  }

  return (
    <div className="bg-white border border-slate-200/90 rounded-xl shadow-xs overflow-hidden">
      {/* Table Header Controls */}
      <div className="p-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white">
        {/* Search */}
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            placeholder="Search by IP, MAC, hostname, or port..."
            className="w-full pl-9 pr-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white transition-colors"
          />
        </div>

        {/* Export & Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadCsv}
            title="Download CSV spreadsheet"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-300 rounded-lg transition-colors"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-blue-600" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleDownloadJson}
            title="Download JSON data"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-300 rounded-lg transition-colors"
          >
            <FileCode className="w-3.5 h-3.5 text-blue-600" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handleCopyJson}
            title="Copy Report JSON"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-300 rounded-lg transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Main Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50/80 text-slate-600 font-semibold text-[11px] uppercase tracking-wider">
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('ip')}
                  className="flex items-center gap-1.5 hover:text-slate-900 font-semibold"
                >
                  <span>IP Address</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </button>
              </th>
              <th className="py-3 px-4">MAC Address</th>
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('hostname')}
                  className="flex items-center gap-1.5 hover:text-slate-900 font-semibold"
                >
                  <span>Hostname</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </button>
              </th>
              <th className="py-3 px-4">
                <button
                  onClick={() => handleSort('ports')}
                  className="flex items-center gap-1.5 hover:text-slate-900 font-semibold"
                >
                  <span>Open Ports</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </button>
              </th>
              <th className="py-3 px-4">Evidence / Method</th>
              <th className="py-3 px-4 text-right">
                <button
                  onClick={() => handleSort('latency')}
                  className="flex items-center gap-1.5 justify-end w-full hover:text-slate-900 font-semibold"
                >
                  <span>Latency</span>
                  <ArrowUpDown className="w-3 h-3 text-slate-400" />
                </button>
              </th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {paginatedDevices.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-10 text-center text-slate-500 text-xs">
                  {searchQuery ? (
                    <div>No discovered devices match your filter query &ldquo;{searchQuery}&rdquo;.</div>
                  ) : (
                    <div>No active devices responded during this scan on target {report.targetNetwork}.</div>
                  )}
                </td>
              </tr>
            ) : (
              paginatedDevices.map((device) => (
                <tr
                  key={device.ipAddress}
                  onClick={() => onSelectDevice(device)}
                  className="hover:bg-slate-50/70 transition-colors cursor-pointer group"
                >
                  {/* IP Address */}
                  <td className="py-3 px-4 font-mono font-bold text-blue-700 tabular-nums">
                    {device.ipAddress}
                  </td>

                  {/* MAC Address & Vendor */}
                  <td className="py-3 px-4">
                    {device.macAddress ? (
                      <div>
                        <div className="font-mono text-slate-800 tabular-nums">{device.macAddress}</div>
                        {device.vendor && (
                          <div className="text-[11px] text-slate-500">{device.vendor}</div>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-400 italic text-[11px]">N/A (L3 only)</span>
                    )}
                  </td>

                  {/* Hostname */}
                  <td className="py-3 px-4 text-slate-700">
                    {device.hostname ? (
                      <span className="font-mono text-[11px] text-slate-900 font-medium">
                        {device.hostname}
                      </span>
                    ) : (
                      <span className="text-slate-400 text-[11px]">Unresolved</span>
                    )}
                  </td>

                  {/* Open Ports */}
                  <td className="py-3 px-4">
                    {device.openPorts.length > 0 ? (
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {device.openPorts.map((p) => (
                          <span
                            key={p}
                            className="px-1.5 py-0.5 bg-slate-100 border border-slate-200 rounded font-mono text-[11px] text-slate-800 tabular-nums"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-400 text-[11px]">None detected</span>
                    )}
                  </td>

                  {/* Evidence / OS */}
                  <td className="py-3 px-4">
                    <div>
                      <div className="font-medium text-slate-800">{device.osMatch}</div>
                      {device.evidence && (
                        <div className="text-[11px] text-slate-500 truncate max-w-xs" title={device.evidence}>
                          {device.evidence}
                        </div>
                      )}
                    </div>
                  </td>

                  {/* Latency */}
                  <td className="py-3 px-4 text-right font-mono text-slate-700 tabular-nums">
                    {device.latencyMs !== null ? `${device.latencyMs} ms` : '—'}
                  </td>

                  {/* Action */}
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectDevice(device);
                      }}
                      className="p-1 text-slate-400 hover:text-blue-600 rounded hover:bg-slate-100 transition-colors"
                      title="Inspect device details"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination & Status Footer */}
      <div className="px-4 py-3 border-t border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-600 bg-slate-50/50">
        <div className="flex items-center gap-2">
          <span>Showing {paginatedDevices.length} of {filteredDevices.length} hosts</span>
          <span aria-hidden="true">·</span>
          <span>Target: <span className="font-mono font-medium text-slate-800">{report.targetNetwork}</span></span>
          <span aria-hidden="true">·</span>
          <span>Method: <span className="font-sans font-medium uppercase text-slate-800">{report.scanMethod}</span></span>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="p-1 rounded text-slate-500 hover:text-slate-900 disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-slate-700 font-medium">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="p-1 rounded text-slate-500 hover:text-slate-900 disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
