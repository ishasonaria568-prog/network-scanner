import React from 'react';
import {
  Keyboard,
  CheckCircle2,
  Radio,
  HardDrive,
  Cpu,
  FileSpreadsheet,
  ArrowRight,
  AlertTriangle,
  Layers,
  Info,
} from 'lucide-react';

export const HowItWorks: React.FC = () => {
  const steps = [
    {
      step: 'Step 1',
      title: 'Enter a network',
      desc: 'The user enters an IPv4 address or CIDR subnet, such as 192.168.1.0/24 or 127.0.0.1/32, defining the exact IP scope to discover.',
      icon: Keyboard,
    },
    {
      step: 'Step 2',
      title: 'Validate the target',
      desc: 'The application parses the netmask, rejects invalid syntax or oversized ranges (/16 or larger), enforces cloud SSRF safeguards, and checks available scan capabilities.',
      icon: CheckCircle2,
    },
    {
      step: 'Step 3',
      title: 'Discover devices',
      desc: 'For supported local networks, the Python agent sends Layer 2 ARP broadcast frames. For cloud or remote networks, the scanner performs non-blocking Layer 3 TCP connect probes.',
      icon: Radio,
    },
    {
      step: 'Step 4',
      title: 'Collect device information',
      desc: 'Actual responses are recorded: ARP provides IP and MAC addresses; reverse DNS attempts to resolve hostnames; TCP connection probes record port availability and service banners.',
      icon: HardDrive,
    },
    {
      step: 'Step 5',
      title: 'Process results',
      desc: 'A bounded worker thread pool aggregates findings in a thread-safe manner, calculates round-trip latency, applies evidence-backed OS rules, and logs any network timeouts.',
      icon: Cpu,
    },
    {
      step: 'Step 6',
      title: 'Display and export',
      desc: 'The interface presents discovered hosts in a searchable, sortable table and enables structured exports to CSV or JSON formats for documentation.',
      icon: FileSpreadsheet,
    },
  ];

  const diagramSteps = [
    { label: 'User Input', sub: 'IP or CIDR' },
    { label: 'Validation', sub: 'Scope & SSRF' },
    { label: 'Scan Engine', sub: 'ARP / TCP' },
    { label: 'Processing', sub: 'DNS & Evidence' },
    { label: 'Results Table', sub: 'Live Inventory' },
    { label: 'Export', sub: 'CSV & JSON' },
  ];

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">How Network Scanning Works</h2>
        <p className="text-xs text-slate-600 mt-1 max-w-2xl leading-relaxed">
          An educational guide to the end-to-end discovery lifecycle, protocol layers, and technical boundaries.
        </p>
      </div>

      {/* Visual Flow Diagram */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-4">
          Visual Scanning Architecture Flow
        </h3>

        {/* Desktop / Tablet Flow */}
        <div className="hidden md:flex items-center justify-between gap-2 overflow-x-auto py-2">
          {diagramSteps.map((item, idx) => (
            <React.Fragment key={idx}>
              <div className="flex-1 bg-slate-50 border border-slate-200 rounded-lg p-3 text-center min-w-[110px]">
                <div className="text-xs font-bold text-slate-900">{item.label}</div>
                <div className="text-[11px] text-slate-500 font-mono mt-0.5">{item.sub}</div>
              </div>
              {idx < diagramSteps.length - 1 && (
                <ArrowRight className="w-4 h-4 text-blue-500 shrink-0" />
              )}
            </React.Fragment>
          ))}
        </div>

        {/* Mobile Flow */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 md:hidden">
          {diagramSteps.map((item, idx) => (
            <div key={idx} className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-center">
              <div className="text-[11px] font-mono text-blue-600 font-semibold mb-0.5">0{idx + 1}</div>
              <div className="text-xs font-bold text-slate-900">{item.label}</div>
              <div className="text-[10px] text-slate-500">{item.sub}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Numbered Steps Sequence */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {steps.map((st, idx) => {
          const Icon = st.icon;
          return (
            <div
              key={idx}
              className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-mono font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-200/60">
                    {st.step}
                  </span>
                  <div className="w-8 h-8 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-center text-slate-600">
                    <Icon className="w-4 h-4 text-slate-700" />
                  </div>
                </div>
                <h4 className="text-sm font-bold text-slate-900 mb-1.5">{st.title}</h4>
                <p className="text-xs text-slate-600 leading-relaxed">{st.desc}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Important Limitations Box */}
      <div className="bg-amber-50/70 border border-amber-200 rounded-xl p-6 shadow-xs">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0" />
          <h3 className="text-sm font-bold text-amber-950">
            Important Protocol &amp; Network Limitations
          </h3>
        </div>

        <p className="text-xs text-amber-900 mb-3 leading-relaxed">
          Reliable network security analysis requires recognizing what different protocols can and cannot observe:
        </p>

        <ul className="text-xs text-amber-900 space-y-2 leading-relaxed">
          <li className="flex items-start gap-2">
            <span className="font-bold text-amber-700 shrink-0">•</span>
            <span>
              <strong>ARP requires local network segment access:</strong> Address Resolution Protocol frames (<code className="bg-white px-1 py-0.5 rounded border border-amber-200 font-mono text-[11px]">who-has</code>) do not route across Internet gateways. ARP discovery works only within your local broadcast domain.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <span className="font-bold text-amber-700 shrink-0">•</span>
            <span>
              <strong>MAC addresses are not obtainable across the Internet:</strong> When scanning a remote WAN or cloud address via TCP, intermediate routers overwrite the Ethernet frame. Only the next-hop router MAC is visible, not the end target's physical MAC.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <span className="font-bold text-amber-700 shrink-0">•</span>
            <span>
              <strong>Reverse DNS does not guarantee hostnames:</strong> Reverse DNS (PTR records) must be explicitly configured by network administrators. If unconfigured or blocked, the scanner accurately reports <em>Unresolved</em> instead of guessing.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <span className="font-bold text-amber-700 shrink-0">•</span>
            <span>
              <strong>Unresponsive does not mean offline:</strong> Host-based firewalls (such as Windows Defender Firewall or Linux iptables) frequently drop unsolicited TCP SYN probes or ICMP pings without replying.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <span className="font-bold text-amber-700 shrink-0">•</span>
            <span>
              <strong>TCP port scanning differs from ARP discovery:</strong> TCP connect probes verify if specific application services (like HTTP or SSH) are accepting connections, whereas ARP discovers physical hardware link connections.
            </span>
          </li>
        </ul>
      </div>
    </div>
  );
};
