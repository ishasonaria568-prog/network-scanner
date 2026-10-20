/**
 * Network Scanner Web Application
 * Built by Isha Sonaria
 *
 * Professional, clean, light-themed networking utility for discovering
 * and inspecting devices on authorized networks.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Navbar, NavTab } from './components/Navbar';
import { SummaryCards } from './components/SummaryCards';
import { MainScanPanel } from './components/MainScanPanel';
import { ResultsTable } from './components/ResultsTable';
import { HowItWorks } from './components/HowItWorks';
import { CliGuide } from './components/CliGuide';
import { SettingsConnection } from './components/SettingsConnection';
import { DeviceDetailModal } from './components/DeviceDetailModal';
import { Footer } from './components/Footer';
import { CapabilitiesResponse, DiscoveredDevice, ScanReport } from './types';
import {
  AlertTriangle,
  History,
  ArrowRight,
  ShieldAlert,
  CheckCircle,
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('scanner');
  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [activeReport, setActiveReport] = useState<ScanReport | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanReport[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<DiscoveredDevice | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Load capabilities & history
  const fetchCapabilities = useCallback(async () => {
    try {
      const res = await fetch('/api/capabilities');
      if (res.ok) {
        const data = await res.json();
        setCapabilities(data);
      }
    } catch {
      // Fallback
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch('/api/history');
      if (res.ok) {
        const data = await res.json();
        if (data.scans) {
          setScanHistory(data.scans);
          if (data.scans.length > 0 && !activeReport) {
            setActiveReport(data.scans[0]);
          }
        }
      }
    } catch {
      // Fallback
    }
  }, [activeReport]);

  useEffect(() => {
    fetchCapabilities();
    fetchHistory();
    const interval = setInterval(fetchCapabilities, 10000);
    return () => clearInterval(interval);
  }, [fetchCapabilities, fetchHistory]);

  // Execute scan
  const handleStartScan = async (params: {
    target: string;
    method: 'tcp_connect' | 'arp_discovery';
    ports: string;
    timeout: number;
    authorized: boolean;
  }) => {
    setIsScanning(true);
    setScanError(null);

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.message || data.error || 'Scan request failed.');
      }

      // If delegated to external agent, poll for completion
      if (data.delegated_to_agent) {
        const jobId = data.scan_id;
        let attempts = 0;
        const maxAttempts = 35; // 35 * 1.5s = 52s max wait

        const pollInterval = setInterval(async () => {
          attempts++;
          try {
            const pollRes = await fetch(`/api/scans/${jobId}`);
            if (pollRes.ok) {
              const report = await pollRes.json();
              if (report.status === 'completed' || report.status === 'failed' || report.status === 'partial') {
                clearInterval(pollInterval);
                setActiveReport(report);
                setIsScanning(false);
                fetchHistory();
                setActiveTab('results');
              }
            }
          } catch {
            // Keep polling
          }

          if (attempts >= maxAttempts) {
            clearInterval(pollInterval);
            setIsScanning(false);
            setScanError('Timed out waiting for external agent response. Please verify that your Kali agent is active and listening.');
          }
        }, 1500);
      } else {
        // Direct TCP connect scan completed on server
        setActiveReport(data);
        setIsScanning(false);
        fetchHistory();
        setActiveTab('results');
      }
    } catch (err: any) {
      setIsScanning(false);
      setScanError(err.message || 'Scan execution failed');
      throw err;
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        capabilities={capabilities}
        resultCount={activeReport ? activeReport.discoveredDevices.length : 0}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 pt-6 pb-12">
        {/* Global Error Banner if Scan Failed */}
        {scanError && (
          <div className="mb-6 p-4 bg-rose-50 border border-rose-200 rounded-xl flex items-start justify-between text-xs text-rose-800 shadow-xs">
            <div className="flex items-start gap-2.5">
              <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold block text-rose-900">Scan Warning or Error</span>
                <span>{scanError}</span>
              </div>
            </div>
            <button
              onClick={() => setScanError(null)}
              className="text-xs font-semibold text-rose-700 hover:text-rose-900 ml-4 shrink-0"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Section 1: Scanner (Main Dashboard) */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            {/* Metric Summary Cards */}
            <SummaryCards
              report={activeReport}
              isScanning={isScanning}
              capabilities={capabilities}
            />

            {/* Main Scan Panel (Directly on the page) */}
            <MainScanPanel
              onStartScan={handleStartScan}
              isScanning={isScanning}
              capabilities={capabilities}
            />

            {/* Quick Preview of Latest Results if available */}
            {activeReport && activeReport.discoveredDevices.length > 0 && (
              <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                    <span className="font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                      Scan Completed
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>Target: <strong className="text-slate-800 font-mono">{activeReport.targetNetwork}</strong></span>
                    <span aria-hidden="true">·</span>
                    <span>Elapsed: {activeReport.durationSeconds.toFixed(2)}s</span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-900">
                    Discovered {activeReport.discoveredDevices.length} active {activeReport.discoveredDevices.length === 1 ? 'host' : 'hosts'}
                  </h3>
                </div>

                <button
                  onClick={() => setActiveTab('results')}
                  className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-blue-700 hover:text-blue-800 bg-blue-50 hover:bg-blue-100 rounded-lg border border-blue-200 transition-colors whitespace-nowrap self-start sm:self-auto"
                >
                  <span>View Full Results Table</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        )}

        {/* Section 2: Results Table */}
        {activeTab === 'results' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h2 className="text-xl font-bold text-slate-900 tracking-tight">Discovered Device Results</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Review active hosts, physical MAC addresses, open ports, and validated OS evidence
                </p>
              </div>

              {activeReport && (
                <button
                  onClick={() => setActiveTab('scanner')}
                  className="text-xs font-semibold text-blue-600 hover:text-blue-700 transition-colors self-start sm:self-auto"
                >
                  &larr; Configure New Scan
                </button>
              )}
            </div>

            <ResultsTable
              report={activeReport}
              onSelectDevice={(device) => setSelectedDevice(device)}
              onNavigateToScanner={() => setActiveTab('scanner')}
            />

            {/* Historical Scans Drawer */}
            {scanHistory.length > 1 && (
              <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                    <History className="w-3.5 h-3.5 text-slate-500" />
                    <span>Previous Scans in Current Session ({scanHistory.length})</span>
                  </h3>
                  <span className="text-[11px] text-slate-500">Session cache</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  {scanHistory.map((scan) => {
                    const isCurrent = activeReport?.scanId === scan.scanId;
                    return (
                      <button
                        key={scan.scanId}
                        type="button"
                        onClick={() => setActiveReport(scan)}
                        className={`p-3 text-left rounded-lg border transition-all ${
                          isCurrent
                            ? 'border-blue-500 bg-blue-50/50 ring-1 ring-blue-500/20'
                            : 'border-slate-200 hover:border-slate-300 bg-slate-50/50'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono text-xs font-bold text-slate-900">
                            {scan.targetNetwork}
                          </span>
                          <span className="text-[10px] uppercase font-mono text-slate-500">
                            {scan.scanMethod === 'arp_discovery' ? 'ARP' : 'TCP'}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 flex items-center justify-between">
                          <span>{scan.discoveredDevices.length} hosts found</span>
                          <span className="font-mono">{scan.durationSeconds.toFixed(1)}s</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Section 3: How It Works */}
        {activeTab === 'how-it-works' && <HowItWorks />}

        {/* Section 4: CLI Guide */}
        {activeTab === 'cli-guide' && <CliGuide />}

        {/* Section 5: Settings & Connection */}
        {activeTab === 'settings' && (
          <SettingsConnection
            capabilities={capabilities}
            onRefresh={fetchCapabilities}
          />
        )}
      </main>

      {/* Footer */}
      <Footer />

      {/* Device Detail Inspection Modal */}
      <DeviceDetailModal
        device={selectedDevice}
        onClose={() => setSelectedDevice(null)}
      />
    </div>
  );
}
