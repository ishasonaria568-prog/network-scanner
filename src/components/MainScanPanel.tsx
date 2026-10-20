import React, { useState } from 'react';
import {
  Play,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  CheckSquare,
  Square,
  AlertCircle,
  Network,
  Cpu,
  Shield,
  Loader2,
} from 'lucide-react';
import { CapabilitiesResponse } from '../types';

interface MainScanPanelProps {
  onStartScan: (params: {
    target: string;
    method: 'tcp_connect' | 'arp_discovery';
    ports: string;
    timeout: number;
    authorized: boolean;
  }) => Promise<void>;
  isScanning: boolean;
  capabilities: CapabilitiesResponse | null;
}

export const MainScanPanel: React.FC<MainScanPanelProps> = ({
  onStartScan,
  isScanning,
  capabilities,
}) => {
  const [target, setTarget] = useState('');
  const [method, setMethod] = useState<'tcp_connect' | 'arp_discovery'>('tcp_connect');
  const [portPreset, setPortPreset] = useState<'standard' | 'web' | 'infra' | 'custom'>('standard');
  const [customPorts, setCustomPorts] = useState('22,80,443,445,8080');
  const [timeoutMs, setTimeoutMs] = useState(1200);
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showCidrHelp, setShowCidrHelp] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const isAgentOnline = Boolean(capabilities?.external_agent_configured);

  const getEffectivePorts = () => {
    switch (portPreset) {
      case 'standard':
        return '22,80,443,445,8080';
      case 'web':
        return '80,443,8000,8080,8443';
      case 'infra':
        return '21,22,23,25,53,135,139,445,3389';
      case 'custom':
        return customPorts;
    }
  };

  const handleQuickPreset = (presetTarget: string) => {
    setTarget(presetTarget);
    setValidationError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    const trimmed = target.trim();
    if (!trimmed) {
      setValidationError('Please enter a target IPv4 address or CIDR subnet (e.g. 192.168.1.0/24 or 127.0.0.1/32).');
      return;
    }

    if (!isAuthorized) {
      setValidationError('Authorization required: You must confirm you own or have explicit written permission to scan this network.');
      return;
    }

    if (method === 'arp_discovery' && !isAgentOnline) {
      setValidationError(
        'Layer 2 ARP discovery requires the External Scanner Agent to be running on your local network. ' +
        'Please start the agent from the "Settings & Connection" tab, or choose "Layer 3 TCP Connect" for cloud-based scanning.'
      );
      return;
    }

    try {
      await onStartScan({
        target: trimmed,
        method,
        ports: getEffectivePorts(),
        timeout: timeoutMs,
        authorized: isAuthorized,
      });
    } catch (err: any) {
      setValidationError(err.message || 'Scan request failed.');
    }
  };

  return (
    <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs mb-8">
      {/* Title & Introduction */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-5 border-b border-slate-100 gap-2">
        <div>
          <h2 className="text-base font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Network className="w-4 h-4 text-blue-600" />
            <span>Configure &amp; Start Network Discovery</span>
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Specify a target subnet or host to discover active devices and inspect services
          </p>
        </div>

        <button
          type="button"
          onClick={() => setShowCidrHelp(!showCidrHelp)}
          className="flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-700 font-medium self-start sm:self-auto"
        >
          <HelpCircle className="w-3.5 h-3.5" />
          <span>{showCidrHelp ? 'Hide CIDR Guide' : 'What is CIDR?'}</span>
        </button>
      </div>

      {/* CIDR Educational Explainer Box */}
      {showCidrHelp && (
        <div className="mb-5 p-4 bg-blue-50/70 border border-blue-200/80 rounded-xl text-xs text-slate-700 leading-relaxed space-y-2">
          <div className="font-semibold text-blue-900 flex items-center gap-1.5">
            <HelpCircle className="w-4 h-4 text-blue-600 shrink-0" />
            <span>Understanding CIDR (Classless Inter-Domain Routing) Notation</span>
          </div>
          <p>
            CIDR notation describes a range of IP addresses using a base IP followed by a slash and prefix length (such as <code className="bg-white px-1.5 py-0.5 rounded border border-blue-200 font-mono text-blue-950">192.168.1.0/24</code>).
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1 font-mono text-[11px]">
            <div className="bg-white p-2.5 rounded-lg border border-blue-200/70">
              <span className="font-bold text-slate-900 block">/32 (Single Host)</span>
              <span className="text-slate-500 font-sans">e.g. 127.0.0.1/32 probes exactly 1 address</span>
            </div>
            <div className="bg-white p-2.5 rounded-lg border border-blue-200/70">
              <span className="font-bold text-slate-900 block">/24 (Standard Subnet)</span>
              <span className="text-slate-500 font-sans">e.g. 192.168.1.0/24 probes 254 host addresses (.1 to .254)</span>
            </div>
            <div className="bg-white p-2.5 rounded-lg border border-blue-200/70">
              <span className="font-bold text-slate-900 block">/29 (Small Office)</span>
              <span className="text-slate-500 font-sans">e.g. 10.0.0.0/29 probes 6 host addresses (.1 to .6)</span>
            </div>
          </div>
        </div>
      )}

      {/* Main Form */}
      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Row 1: Target Input + Presets */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="target-network" className="text-xs font-semibold text-slate-800">
              Target Network or IP Address <span className="text-rose-500">*</span>
            </label>
            <span className="text-xs text-slate-600">
              Example: <span className="font-mono text-slate-700 font-medium">192.168.1.0/24</span> or <span className="font-mono text-slate-700 font-medium">127.0.0.1/32</span>
            </span>
          </div>

          <div className="relative">
            <input
              id="target-network"
              type="text"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                setValidationError(null);
              }}
              placeholder="e.g. 192.168.1.0/24 or 127.0.0.1/32"
              className={`w-full px-3.5 py-2.5 bg-slate-50 border rounded-lg text-sm font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white transition-colors ${
                validationError
                  ? 'border-rose-400 focus:border-rose-500 focus:ring-1 focus:ring-rose-400'
                  : 'border-slate-300 focus:border-blue-600 focus:ring-1 focus:ring-blue-600'
              }`}
            />
          </div>

          {/* Preset Buttons */}
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <span className="text-xs text-slate-600 font-medium">Quick presets:</span>
            <button
              type="button"
              onClick={() => handleQuickPreset('127.0.0.1/32')}
              className="text-xs font-mono text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200/80 px-2.5 py-1 rounded-md border border-slate-200 transition-colors"
            >
              127.0.0.1/32 (Localhost)
            </button>
            <button
              type="button"
              onClick={() => handleQuickPreset('192.168.1.0/24')}
              className="text-xs font-mono text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200/80 px-2.5 py-1 rounded-md border border-slate-200 transition-colors"
            >
              192.168.1.0/24 (Local LAN)
            </button>
            <button
              type="button"
              onClick={() => handleQuickPreset('10.0.0.0/24')}
              className="text-xs font-mono text-slate-600 hover:text-slate-900 bg-slate-100 hover:bg-slate-200/80 px-2.5 py-1 rounded-md border border-slate-200 transition-colors"
            >
              10.0.0.0/24 (Private Network)
            </button>
          </div>
        </div>

        {/* Row 2: Scan Method Selector */}
        <div>
          <label className="block text-xs font-semibold text-slate-800 mb-1.5">
            Scan Method
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* Option A: Layer 3 TCP Connect */}
            <div
              onClick={() => setMethod('tcp_connect')}
              className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                method === 'tcp_connect'
                  ? 'border-blue-500 bg-blue-50/40 ring-1 ring-blue-500/20'
                  : 'border-slate-200 bg-white hover:border-slate-300'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                  <span className={`w-3 h-3 rounded-full border flex items-center justify-center ${method === 'tcp_connect' ? 'border-blue-600' : 'border-slate-300'}`}>
                    {method === 'tcp_connect' && <span className="w-1.5 h-1.5 bg-blue-600 rounded-full" />}
                  </span>
                  Layer 3 TCP Connect Probing
                </span>
                <span className="text-[11px] font-sans font-medium text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                  Cloud Ready
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-1 pl-4.5 leading-relaxed">
                Connects directly to selected ports. Safe and non-destructive. Works in Vercel serverless without elevated privileges.
              </p>
            </div>

            {/* Option B: Layer 2 ARP Discovery */}
            <div
              onClick={() => setMethod('arp_discovery')}
              className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                method === 'arp_discovery'
                  ? 'border-blue-500 bg-blue-50/40 ring-1 ring-blue-500/20'
                  : 'border-slate-200 bg-white hover:border-slate-300'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                  <span className={`w-3 h-3 rounded-full border flex items-center justify-center ${method === 'arp_discovery' ? 'border-blue-600' : 'border-slate-300'}`}>
                    {method === 'arp_discovery' && <span className="w-1.5 h-1.5 bg-blue-600 rounded-full" />}
                  </span>
                  Layer 2 ARP Discovery
                </span>
                <span
                  className={`text-[11px] font-sans font-medium px-2 py-0.5 rounded-full border ${
                    isAgentOnline
                      ? 'text-emerald-800 bg-emerald-50 border-emerald-200'
                      : 'text-amber-800 bg-amber-50 border-amber-200'
                  }`}
                >
                  {isAgentOnline ? 'Agent Ready' : 'Agent Needed'}
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-1 pl-4.5 leading-relaxed">
                Broadcasts Ethernet ARP requests on physical LAN. Captures physical MAC addresses. Routed through your local Kali Linux agent.
              </p>
            </div>
          </div>
        </div>

        {/* Row 3: Optional Port Profile Selection */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="text-xs font-semibold text-slate-800">
              TCP Ports to Probe
            </label>
            <span className="text-xs text-slate-600 font-mono">
              Selected: {getEffectivePorts()}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {[
              { id: 'standard', label: 'Standard Services', sub: '22, 80, 443, 445, 8080' },
              { id: 'web', label: 'Web Only', sub: '80, 443, 8000, 8080' },
              { id: 'infra', label: 'Infrastructure', sub: '21, 22, 25, 53, 3389' },
              { id: 'custom', label: 'Custom List', sub: 'Specify ports' },
            ].map((p) => {
              const isSelected = portPreset === p.id;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setPortPreset(p.id as any)}
                  className={`p-2.5 text-left rounded-lg border transition-all ${
                    isSelected
                      ? 'border-blue-500 bg-blue-50/50 text-blue-900 font-semibold'
                      : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300'
                  }`}
                >
                  <div className="text-xs">{p.label}</div>
                  <div className="text-[11px] font-mono text-slate-600 mt-0.5 truncate">{p.sub}</div>
                </button>
              );
            })}
          </div>

          {portPreset === 'custom' && (
            <div className="mt-2.5">
              <input
                type="text"
                value={customPorts}
                onChange={(e) => setCustomPorts(e.target.value)}
                placeholder="e.g. 22,80,443,8080 or 80-90"
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">
                Enter comma-separated ports or ranges (e.g. 80-88, 443, 8080)
              </span>
            </div>
          )}
        </div>

        {/* Collapsible Advanced Settings */}
        <div className="border border-slate-200 rounded-lg overflow-hidden">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full px-4 py-2.5 bg-slate-50/80 hover:bg-slate-100/80 flex items-center justify-between text-xs font-medium text-slate-700 transition-colors"
          >
            <span>Advanced Concurrency &amp; Timeout Settings</span>
            {showAdvanced ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </button>

          {showAdvanced && (
            <div className="p-4 bg-white border-t border-slate-200 space-y-4">
              <div>
                <div className="flex items-center justify-between text-xs text-slate-700 mb-1">
                  <span>Socket Connect Timeout</span>
                  <span className="font-mono font-semibold text-slate-900">{timeoutMs} ms</span>
                </div>
                <input
                  type="range"
                  min="200"
                  max="3000"
                  step="100"
                  value={timeoutMs}
                  onChange={(e) => setTimeoutMs(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Lower timeout = faster overall scan; Higher timeout = reliable over slow Wi-Fi or high-latency WANs.
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Mandatory Authorization Confirmation Checkbox */}
        <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
          <button
            type="button"
            onClick={() => {
              setIsAuthorized(!isAuthorized);
              setValidationError(null);
            }}
            className="flex items-start gap-2.5 text-left w-full group"
          >
            <div className="mt-0.5 text-blue-600 shrink-0">
              {isAuthorized ? (
                <CheckSquare className="w-4 h-4 fill-blue-600 text-white" />
              ) : (
                <Square className="w-4 h-4 text-slate-400 group-hover:text-slate-600" />
              )}
            </div>
            <div className="text-xs text-slate-700 leading-relaxed select-none">
              <span className="font-semibold text-slate-900">Mandatory Authorization:</span> I confirm that I own or have explicit written authorization from the owner to scan this target network. This utility is strictly intended for authorized defensive administration and inventory.
            </div>
          </button>
        </div>

        {/* Validation Error Banner */}
        {validationError && (
          <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg flex items-start gap-2 text-xs text-rose-700">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
            <span>{validationError}</span>
          </div>
        )}

        {/* Action Button */}
        <div className="flex items-center justify-between pt-1">
          <span className="text-xs text-slate-500">
            {target.trim() ? `Ready to scan ${target.trim()}` : 'Enter an authorized network to begin'}
          </span>

          <button
            type="submit"
            disabled={isScanning || !isAuthorized}
            className="flex items-center gap-2 px-6 py-2.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg shadow-xs transition-all whitespace-nowrap"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Executing Scan...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Scan</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Live Scan In-Progress Feedback */}
      {isScanning && (
        <div className="mt-6 p-4 bg-blue-50/70 border border-blue-200 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-blue-900 flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 text-blue-600 animate-spin" />
              <span>Network scan in progress...</span>
            </span>
            <span className="text-xs font-mono text-blue-700 font-medium">Please wait</span>
          </div>
          <div className="w-full bg-blue-200/80 rounded-full h-1.5 overflow-hidden">
            <div className="bg-blue-600 h-1.5 rounded-full w-2/3 animate-pulse" />
          </div>
          <p className="text-[11px] text-blue-700 mt-2">
            Enumerating hosts, probing responsive TCP ports, and querying reverse DNS records. Results will render automatically below once complete.
          </p>
        </div>
      )}
    </div>
  );
};
