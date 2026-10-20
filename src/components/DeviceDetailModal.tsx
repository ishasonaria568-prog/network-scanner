import React, { useState } from 'react';
import { DiscoveredDevice } from '../types';
import { X, Copy, Check, Server, Shield } from 'lucide-react';

interface DeviceDetailModalProps {
  device: DiscoveredDevice | null;
  onClose: () => void;
}

export const DeviceDetailModal: React.FC<DeviceDetailModalProps> = ({ device, onClose }) => {
  const [copiedField, setCopiedField] = useState<string | null>(null);

  if (!device) return null;

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
      <div className="relative w-full max-w-xl bg-white border border-slate-200 rounded-2xl shadow-xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-slate-50/50">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 font-mono">{device.ipAddress}</h3>
              <p className="text-xs text-slate-500">
                {device.hostname || 'Unresolved Reverse DNS'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5 max-h-[80vh] overflow-y-auto">
          {/* Identity Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
              <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                <span>IPv4 Address</span>
                <button
                  onClick={() => copyToClipboard(device.ipAddress, 'ip')}
                  className="text-slate-400 hover:text-slate-700"
                >
                  {copiedField === 'ip' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="text-sm font-mono font-bold text-blue-700">{device.ipAddress}</div>
            </div>

            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
              <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                <span>MAC Address</span>
                {device.macAddress && (
                  <button
                    onClick={() => copyToClipboard(device.macAddress!, 'mac')}
                    className="text-slate-400 hover:text-slate-700"
                  >
                    {copiedField === 'mac' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                )}
              </div>
              <div className="text-sm font-mono font-semibold text-slate-900">
                {device.macAddress || <span className="text-slate-400 font-normal italic">N/A (L3 TCP only)</span>}
              </div>
              {device.vendor && (
                <div className="text-[11px] text-slate-500 mt-0.5">{device.vendor}</div>
              )}
            </div>
          </div>

          {/* OS & Fingerprint Evidence Section */}
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                <Shield className="w-4 h-4 text-blue-600" />
                <span>Evidence-Based OS Fingerprint</span>
              </span>
              <span className="text-[11px] text-slate-500 font-mono">
                {device.osMatch === 'Unknown' ? 'Confidence: Inconclusive' : 'Confidence: Verified'}
              </span>
            </div>
            <div className="text-sm font-bold text-slate-900">{device.osMatch}</div>
            <p className="text-xs text-slate-600 mt-1.5 bg-white p-2.5 rounded-lg border border-slate-200 font-mono leading-relaxed">
              {device.evidence || 'No fingerprint evidence recorded.'}
            </p>
          </div>

          {/* Open Ports Table */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 mb-2">
              Detected Port Findings ({device.portDetails.length})
            </h4>

            {device.portDetails.length === 0 ? (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl text-center text-xs text-slate-500">
                No open TCP ports detected or tested on this host.
              </div>
            ) : (
              <div className="border border-slate-200 rounded-xl overflow-hidden bg-white">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-semibold text-[11px]">
                      <th className="py-2.5 px-3">Port</th>
                      <th className="py-2.5 px-3">Service</th>
                      <th className="py-2.5 px-3">State</th>
                      <th className="py-2.5 px-3">Latency</th>
                      <th className="py-2.5 px-3">Banner / Info</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono">
                    {device.portDetails.map((p) => (
                      <tr key={p.port} className="hover:bg-slate-50">
                        <td className="py-2.5 px-3 font-semibold text-blue-700">{p.port}</td>
                        <td className="py-2.5 px-3 text-slate-800 font-sans">{p.service}</td>
                        <td className="py-2.5 px-3 text-emerald-700 font-medium">{p.state}</td>
                        <td className="py-2.5 px-3 text-slate-600">
                          {p.responseTimeMs !== null ? `${p.responseTimeMs} ms` : '—'}
                        </td>
                        <td className="py-2.5 px-3 text-slate-500 text-[11px] truncate max-w-xs font-sans">
                          {p.banner || <span className="text-slate-400 italic">None</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-200 bg-slate-50/50 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-slate-700 hover:text-slate-900 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
