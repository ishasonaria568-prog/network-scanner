import React, { useState } from 'react';
import { Terminal, Copy, Check, Shield, BookOpen, AlertCircle, Play, Globe } from 'lucide-react';

export const CliGuide: React.FC = () => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [builderTarget, setBuilderTarget] = useState('192.168.1.0/24');
  const [builderThreads, setBuilderThreads] = useState(30);
  const [builderPorts, setBuilderPorts] = useState('22,80,443');
  const [builderFormat, setBuilderFormat] = useState<'table' | 'json' | 'csv'>('table');
  const [copiedBuilder, setCopiedBuilder] = useState(false);

  const copyCode = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const generatedCommand = `sudo python3 -m network_scanner scan --network ${builderTarget} --threads ${builderThreads}${
    builderPorts ? ` --ports ${builderPorts}` : ''
  }${builderFormat !== 'table' ? ` --format ${builderFormat}` : ''}`;

  const copyBuilderCommand = () => {
    navigator.clipboard.writeText(generatedCommand);
    setCopiedBuilder(true);
    setTimeout(() => setCopiedBuilder(false), 2000);
  };

  const webSteps = [
    { num: 1, title: 'Understand scan methods', text: 'Select Layer 3 TCP for cloud-compatible port discovery, or Layer 2 ARP (via local agent) for hardware MAC addresses.' },
    { num: 2, title: 'Enter an authorized target', text: 'Input an IPv4 address or CIDR range you own or have explicit written permission to assess (e.g. 192.168.1.0/24 or 127.0.0.1/32).' },
    { num: 3, title: 'Select scan method & ports', text: 'Pick your desired scan profile (Standard, Web Only, Infrastructure, or Custom ports).' },
    { num: 4, title: 'Review settings & authorize', text: 'Confirm the mandatory security authorization checkbox confirming target ownership.' },
    { num: 5, title: 'Start the scan', text: 'Click "Start Scan" and wait for real responses to be collected safely.' },
    { num: 6, title: 'Review results & evidence', text: 'Inspect discovered host IP addresses, hostnames, open ports, and evidence-backed OS signatures.' },
    { num: 7, title: 'Export findings', text: 'Download a structured CSV spreadsheet or JSON file for defensive documentation.' },
  ];

  const cliSteps = [
    {
      title: '1. Clone repository & create virtual environment',
      command: `git clone https://github.com/ishasonaria568-prog/network-scanner.git
cd network-scanner

python3 -m venv .venv
source .venv/bin/activate`,
    },
    {
      title: '2. Install dependencies (Scapy, Requests, Pytest)',
      command: `python -m pip install --upgrade pip
pip install -r requirements.txt`,
    },
    {
      title: '3. Verify platform capabilities & permissions',
      command: `python -m network_scanner capabilities`,
    },
    {
      title: '4. Execute Layer 2 ARP scan (requires sudo for Scapy on Linux)',
      command: `sudo python -m network_scanner scan --network 192.168.1.0/24`,
    },
    {
      title: '5. Scan with port discovery and export to CSV',
      command: `sudo python -m network_scanner scan --network 192.168.1.0/24 --threads 50 --ports 22,80,443 --output results.csv`,
    },
  ];

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">Getting Started &amp; CLI Guide</h2>
        <p className="text-xs text-slate-600 mt-1 max-w-2xl leading-relaxed">
          Beginner-friendly step-by-step instructions for running the Web GUI and executing the standalone Python CLI on Kali Linux or Linux workstations.
        </p>
      </div>

      {/* Part 1: Web GUI Step-by-Step Guide */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
        <div className="flex items-center gap-2 mb-4">
          <Globe className="w-5 h-5 text-blue-600" />
          <h3 className="text-sm font-bold text-slate-900">Step-by-Step Guide for the Web GUI</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {webSteps.map((s) => (
            <div key={s.num} className="p-3.5 bg-slate-50 border border-slate-200/80 rounded-lg">
              <div className="flex items-center gap-2 mb-1.5">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white font-mono text-[11px] font-bold flex items-center justify-center shrink-0">
                  {s.num}
                </span>
                <span className="text-xs font-bold text-slate-900">{s.title}</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed pl-7">{s.text}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Part 2: Interactive CLI Command Builder */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
        <div className="flex items-center gap-2 mb-4">
          <Terminal className="w-5 h-5 text-blue-600" />
          <h3 className="text-sm font-bold text-slate-900">Interactive CLI Command Builder</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
          <div>
            <label className="block text-[11px] font-semibold text-slate-700 mb-1">Target CIDR</label>
            <input
              type="text"
              value={builderTarget}
              onChange={(e) => setBuilderTarget(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:bg-white"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-700 mb-1">Threads ({builderThreads})</label>
            <input
              type="number"
              min="1"
              max="200"
              value={builderThreads}
              onChange={(e) => setBuilderThreads(Number(e.target.value))}
              className="w-full px-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:bg-white"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-700 mb-1">Ports to Probe</label>
            <input
              type="text"
              value={builderPorts}
              onChange={(e) => setBuilderPorts(e.target.value)}
              placeholder="e.g. 22,80,443"
              className="w-full px-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:bg-white"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-700 mb-1">Output Format</label>
            <select
              value={builderFormat}
              onChange={(e) => setBuilderFormat(e.target.value as any)}
              className="w-full px-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-sans text-slate-900 focus:outline-none focus:border-blue-600 focus:bg-white"
            >
              <option value="table">Table (ANSI Formatted)</option>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </div>
        </div>

        {/* Generated Command Box */}
        <div className="p-3.5 bg-slate-900 rounded-lg flex items-center justify-between gap-4">
          <pre className="text-xs font-mono text-emerald-400 overflow-x-auto select-all">
            {generatedCommand}
          </pre>
          <button
            onClick={copyBuilderCommand}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors shrink-0"
          >
            {copiedBuilder ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedBuilder ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Part 3: Privilege Explanation */}
      <div className="p-4 bg-blue-50/70 border border-blue-200/80 rounded-xl flex items-start gap-3 text-xs text-slate-700 leading-relaxed">
        <AlertCircle className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-900 block mb-0.5">When Elevated Privileges (sudo / root) Are Required:</span>
          <p>
            Operating systems require superuser privileges (<code className="bg-white px-1 py-0.5 rounded border border-blue-200 font-mono text-[11px]">sudo</code>) to craft raw Ethernet frames and listen to Layer 2 ARP broadcasts (<code className="bg-white px-1 py-0.5 rounded border border-blue-200 font-mono text-[11px]">CAP_NET_RAW</code>).
            If you run without <code className="bg-white px-1 py-0.5 rounded border border-blue-200 font-mono text-[11px]">sudo</code>, the scanner cleanly falls back to unprivileged Layer 3 TCP connect discovery and notifies you.
          </p>
        </div>
      </div>

      {/* Part 4: Kali Linux Installation & Execution Steps */}
      <div className="space-y-4">
        <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-blue-600" />
          <span>Kali Linux Installation &amp; Execution Commands</span>
        </h3>

        {cliSteps.map((item, idx) => (
          <div key={idx} className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-800">{item.title}</span>
              <button
                onClick={() => copyCode(item.command, idx)}
                className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-900 transition-colors"
              >
                {copiedIndex === idx ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3 bg-slate-900 rounded-lg text-xs font-mono text-emerald-400 overflow-x-auto leading-relaxed">
              {item.command}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
};
