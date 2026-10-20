import React, { useState, useEffect } from 'react';
import { AgentInfo, CapabilitiesResponse } from '../types';
import {
  Radio,
  Copy,
  Check,
  RefreshCw,
  Terminal,
  ShieldCheck,
  Cpu,
  Layers,
  ChevronDown,
  ChevronUp,
  X,
  AlertCircle,
} from 'lucide-react';

interface SettingsConnectionProps {
  capabilities: CapabilitiesResponse | null;
  onRefresh: () => void;
}

export const SettingsConnection: React.FC<SettingsConnectionProps> = ({
  capabilities,
  onRefresh,
}) => {
  const [token, setToken] = useState<string>('');
  const [isCopiedToken, setIsCopiedToken] = useState(false);
  const [isCopiedCmd, setIsCopiedCmd] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);
  const [showArchDetails, setShowArchDetails] = useState(false);

  useEffect(() => {
    fetch('/api/agent/status')
      .then((res) => res.json())
      .then((data) => {
        if (data.token) setToken(data.token);
      })
      .catch(() => {});
  }, []);

  const handleRegenerateToken = async () => {
    setIsRegenerating(true);
    try {
      const res = await fetch('/api/agent/token/regenerate', { method: 'POST' });
      const data = await res.json();
      if (data.token) setToken(data.token);
    } finally {
      setIsRegenerating(false);
    }
  };

  const appOrigin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  const agentRunCommand = `sudo python3 -m agent.client --server-url ${appOrigin} --token ${token || 'YOUR_TOKEN'}`;

  const copyText = (txt: string, type: 'token' | 'cmd') => {
    navigator.clipboard.writeText(txt);
    if (type === 'token') {
      setIsCopiedToken(true);
      setTimeout(() => setIsCopiedToken(false), 2000);
    } else {
      setIsCopiedCmd(true);
      setTimeout(() => setIsCopiedCmd(false), 2000);
    }
  };

  const agentInfo = capabilities?.agent_info || null;
  const isOnline = Boolean(capabilities?.external_agent_configured);

  const matrixData = [
    {
      feature: 'Layer 2 ARP Discovery',
      cli: 'Direct (Scapy + Root)',
      agent: 'Direct (Scapy + Root)',
      vercel: 'Routed via Agent',
    },
    {
      feature: 'Physical MAC Address',
      cli: 'Extracted from ARP Frame',
      agent: 'Extracted from ARP Frame',
      vercel: 'Via Connected Agent',
    },
    {
      feature: 'Hardware Vendor OUI',
      cli: 'Resolved from MAC',
      agent: 'Resolved from MAC',
      vercel: 'Via Connected Agent',
    },
    {
      feature: 'Layer 3 TCP Connect Probing',
      cli: 'Supported Natively',
      agent: 'Supported Natively',
      vercel: 'Supported Natively',
    },
    {
      feature: 'Reverse DNS Hostname Lookup',
      cli: 'Supported Natively',
      agent: 'Supported Natively',
      vercel: 'Supported Natively',
    },
    {
      feature: 'Evidence-Based OS Match',
      cli: 'Supported Natively',
      agent: 'Supported Natively',
      vercel: 'Supported Natively',
    },
    {
      feature: 'Required Execution Privileges',
      cli: 'Root for ARP; user for TCP',
      agent: 'Root for ARP; user for TCP',
      vercel: 'Unprivileged Serverless Sandbox',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Settings &amp; Connection Status</h2>
          <p className="text-xs text-slate-600 mt-1 max-w-2xl leading-relaxed">
            Configure the external scanner agent, view platform execution limits, and inspect technical compatibility.
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 bg-white hover:bg-slate-50 border border-slate-300 rounded-lg shadow-xs transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Status</span>
        </button>
      </div>

      {/* Agent Bridge Configuration Card */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-100">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${isOnline ? 'bg-emerald-500 ring-4 ring-emerald-500/20' : 'bg-slate-300'}`} />
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                {isOnline ? 'External Scanner Agent: Connected' : 'External Scanner Agent: Disconnected'}
              </h3>
              <p className="text-xs text-slate-500">
                {isOnline
                  ? `Active node: ${agentInfo?.agent_name || 'Agent'} (${agentInfo?.local_ip || 'local'})`
                  : 'Run the standalone Python agent on your local network to enable Layer 2 ARP discovery'}
              </p>
            </div>
          </div>
          <span className="text-xs font-mono text-slate-500 hidden sm:block">
            {isOnline ? `Last ping: ${new Date(agentInfo!.last_heartbeat).toLocaleTimeString()}` : 'Offline'}
          </span>
        </div>

        {/* Token Management */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-slate-800">
              Agent Secret Pairing Token
            </label>
            <div className="p-3 bg-slate-50 border border-slate-300 rounded-lg flex items-center justify-between gap-3">
              <span className="font-mono text-xs text-slate-900 font-medium truncate select-all">
                {token || 'Loading...'}
              </span>
              <button
                onClick={() => copyText(token, 'token')}
                className="p-1.5 text-slate-500 hover:text-slate-900 hover:bg-slate-200/60 rounded transition-colors"
                title="Copy Token"
              >
                {isCopiedToken ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => copyText(token, 'token')}
                className="px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200/80 rounded-md border border-slate-300 transition-colors"
              >
                {isCopiedToken ? 'Copied' : 'Copy Token'}
              </button>
              <button
                onClick={handleRegenerateToken}
                disabled={isRegenerating}
                className="px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200/80 rounded-md border border-slate-300 transition-colors flex items-center gap-1.5 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRegenerating ? 'animate-spin' : ''}`} />
                <span>Regenerate Token</span>
              </button>
            </div>
          </div>

          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 leading-relaxed space-y-1">
            <span className="font-semibold text-slate-900 block">Agent Security Boundary:</span>
            <p>
              The agent verifies every received job against its local subnet allowlist (<code className="bg-white px-1 py-0.5 rounded border border-slate-200 font-mono text-[11px]">--allow-subnet</code>). It executes only structured scans and rejects arbitrary shell commands, preventing remote SSRF misuse.
            </p>
          </div>
        </div>

        {/* Copyable Terminal Command */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-blue-600" />
              <span>Launch Agent on Kali Linux:</span>
            </label>
            <button
              onClick={() => copyText(agentRunCommand, 'cmd')}
              className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-700 font-medium"
            >
              {isCopiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{isCopiedCmd ? 'Copied' : 'Copy Command'}</span>
            </button>
          </div>
          <pre className="p-3 bg-slate-900 rounded-lg text-xs font-mono text-emerald-400 overflow-x-auto select-all">
            {agentRunCommand}
          </pre>
        </div>
      </div>

      {/* Platform Capabilities Breakdown */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
        <h3 className="text-sm font-bold text-slate-900 mb-3 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-blue-600" />
          <span>Active Runtime Platform Capabilities</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-[11px] text-slate-500 block">Environment</span>
            <span className="text-xs font-bold text-slate-900 uppercase">
              {capabilities?.deployment || 'Detecting...'}
            </span>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-[11px] text-slate-500 block">Layer 2 ARP Discovery</span>
            <span className={`text-xs font-bold ${capabilities?.arp_discovery ? 'text-emerald-700' : 'text-slate-600'}`}>
              {capabilities?.arp_discovery ? 'Supported (via Agent)' : 'Agent Required'}
            </span>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <span className="text-[11px] text-slate-500 block">Layer 3 TCP Connect</span>
            <span className="text-xs font-bold text-emerald-700">
              Supported Natively
            </span>
          </div>
        </div>

        {capabilities?.limitations && capabilities.limitations.length > 0 && (
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 space-y-1">
            <span className="font-semibold text-slate-800 block">Environment Notices:</span>
            {capabilities.limitations.map((lim, idx) => (
              <div key={idx} className="flex items-start gap-1.5">
                <span className="text-slate-400">•</span>
                <span>{lim}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Collapsible Architecture Details */}
      <div className="bg-white border border-slate-200/90 rounded-xl overflow-hidden shadow-xs">
        <button
          type="button"
          onClick={() => setShowArchDetails(!showArchDetails)}
          className="w-full p-4 bg-slate-50/80 hover:bg-slate-100 flex items-center justify-between text-left transition-colors"
        >
          <div>
            <h4 className="text-sm font-bold text-slate-900">Technical Architecture &amp; Compatibility Matrix</h4>
            <p className="text-xs text-slate-500 mt-0.5">Detailed comparison of Local CLI vs Local Agent vs Vercel Serverless</p>
          </div>
          {showArchDetails ? <ChevronUp className="w-5 h-5 text-slate-500" /> : <ChevronDown className="w-5 h-5 text-slate-500" />}
        </button>

        {showArchDetails && (
          <div className="p-6 border-t border-slate-200 space-y-6">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-semibold text-[11px] uppercase">
                    <th className="py-2.5 px-3">Feature</th>
                    <th className="py-2.5 px-3">Kali CLI</th>
                    <th className="py-2.5 px-3">Local Agent</th>
                    <th className="py-2.5 px-3">Vercel Serverless</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {matrixData.map((m, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/60">
                      <td className="py-2.5 px-3 font-medium text-slate-900">{m.feature}</td>
                      <td className="py-2.5 px-3 text-slate-700 font-mono text-[11px]">{m.cli}</td>
                      <td className="py-2.5 px-3 text-slate-700 font-mono text-[11px]">{m.agent}</td>
                      <td className="py-2.5 px-3 text-slate-700 font-mono text-[11px]">{m.vercel}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 leading-relaxed space-y-1.5">
              <span className="font-semibold text-slate-900 block">Why Vercel Serverless Cannot Run ARP Broadcasts:</span>
              <p>
                Layer 2 ARP requires non-routable Ethernet broadcast frames (<code className="bg-white px-1 py-0.5 rounded font-mono text-[11px]">FF:FF:FF:FF:FF:FF</code>) on a shared physical switch or virtual LAN.
                Vercel runs in multi-tenant cloud containers with Layer 4 NAT proxies and does not possess Linux kernel capability <code className="bg-white px-1 py-0.5 rounded font-mono text-[11px]">CAP_NET_RAW</code>.
                Our split-plane architecture solves this cleanly by delegating genuine ARP scans to the user&apos;s local Kali agent.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
