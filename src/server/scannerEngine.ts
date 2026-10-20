/**
 * Server-side Network Scanner Engine
 * Built by Isha Sonaria
 *
 * Implements safe, bounded TCP connect scanning, reverse DNS resolution,
 * SSRF guardrails, and conservative OS evidence matching.
 */

import * as dns from 'dns';
import * as net from 'net';

export interface PortFinding {
  port: number;
  service: string;
  state: 'open' | 'closed' | 'filtered';
  banner?: string | null;
  responseTimeMs?: number | null;
}

export interface DiscoveredDevice {
  ipAddress: string;
  macAddress: string | null;
  hostname: string | null;
  vendor: string | null;
  openPorts: number[];
  portDetails: PortFinding[];
  osMatch: string;
  evidence: string | null;
  latencyMs: number | null;
}

export interface ScanReport {
  scanId: string;
  targetNetwork: string;
  scanMethod: 'arp_discovery' | 'tcp_connect' | 'hybrid';
  startedAt: string;
  completedAt: string | null;
  status: 'running' | 'completed' | 'partial' | 'failed';
  durationSeconds: number;
  totalHosts: number;
  discoveredDevices: DiscoveredDevice[];
  errors: string[];
}

export const COMMON_SERVICES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  135: 'msrpc',
  139: 'netbios-ssn',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'microsoft-ds (SMB)',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8000: 'HTTP-Alt',
  8080: 'HTTP-Proxy',
  8443: 'HTTPS-Alt',
  27017: 'MongoDB',
};

// SSRF blacklisted ranges
const BLOCKED_HOSTS = new Set([
  '169.254.169.254', // AWS/GCP/Azure instance metadata
  'metadata.google.internal',
  '100.100.100.200', // Alibaba metadata
]);

export function validateTargetNetwork(target: string, maxHosts = 512): { network: string; hosts: string[] } {
  if (!target || typeof target !== 'string') {
    throw new Error('Target network cannot be empty.');
  }

  const trimmed = target.trim();
  let ip = trimmed;
  let prefix = 32;

  if (trimmed.includes('/')) {
    const parts = trimmed.split('/');
    if (parts.length !== 2) throw new Error('Invalid CIDR format.');
    ip = parts[0].trim();
    prefix = parseInt(parts[1].trim(), 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
      throw new Error('Subnet prefix must be between 0 and 32.');
    }
  }

  // Validate IPv4 format
  const octets = ip.split('.');
  if (octets.length !== 4) {
    throw new Error('Target must be a valid IPv4 address or CIDR subnet (e.g. 192.168.1.0/24).');
  }

  for (const oct of octets) {
    const n = parseInt(oct, 10);
    if (isNaN(n) || n < 0 || n > 255 || oct !== String(n)) {
      throw new Error(`Invalid IPv4 octet value: '${oct}'`);
    }
  }

  // SSRF check
  if (BLOCKED_HOSTS.has(ip)) {
    throw new Error(`Target ${ip} is a restricted cloud metadata address.`);
  }

  const ipNum = (parseInt(octets[0]) << 24) | (parseInt(octets[1]) << 16) | (parseInt(octets[2]) << 8) | parseInt(octets[3]);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const baseIp = (ipNum & mask) >>> 0;
  const totalAddresses = prefix === 32 ? 1 : Math.pow(2, 32 - prefix);

  if (totalAddresses > maxHosts) {
    throw new Error(
      `Requested subnet /${prefix} contains ${totalAddresses} addresses, which exceeds the max safe limit of ${maxHosts} hosts.`
    );
  }

  const hosts: string[] = [];
  if (prefix === 32 || prefix === 31) {
    for (let i = 0; i < totalAddresses; i++) {
      const current = (baseIp + i) >>> 0;
      hosts.push(intToIpv4(current));
    }
  } else {
    // Exclude network and broadcast addresses
    for (let i = 1; i < totalAddresses - 1; i++) {
      const current = (baseIp + i) >>> 0;
      hosts.push(intToIpv4(current));
    }
  }

  const canonical = `${intToIpv4(baseIp)}/${prefix}`;
  return { network: canonical, hosts };
}

function intToIpv4(num: number): string {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255,
  ].join('.');
}

export function parsePortList(portsStr?: string | null): number[] {
  if (!portsStr || typeof portsStr !== 'string') {
    return [80, 443, 22, 445, 8080];
  }

  const unique = new Set<number>();
  const tokens = portsStr.split(',').map((t) => t.trim()).filter(Boolean);

  for (const token of tokens) {
    if (token.includes('-')) {
      const parts = token.split('-');
      if (parts.length === 2) {
        const start = parseInt(parts[0], 10);
        const end = parseInt(parts[1], 10);
        if (!isNaN(start) && !isNaN(end) && start >= 1 && end <= 65535 && start <= end) {
          if (end - start > 200) {
            throw new Error(`Port range ${start}-${end} too large (max 200 ports per range).`);
          }
          for (let p = start; p <= end; p++) unique.add(p);
        }
      }
    } else {
      const p = parseInt(token, 10);
      if (!isNaN(p) && p >= 1 && p <= 65535) {
        unique.add(p);
      }
    }
  }

  return Array.from(unique).sort((a, b) => a - b);
}

export async function resolveReverseDns(ip: string): Promise<string | null> {
  try {
    const hostnames = await dns.promises.reverse(ip);
    return hostnames && hostnames.length > 0 ? hostnames[0] : null;
  } catch {
    return null;
  }
}

export function probeTcpPort(
  ip: string,
  port: number,
  timeoutMs = 1200
): Promise<{ isOpen: boolean; latencyMs: number | null; banner: string | null }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const startTime = Date.now();
    let banner: string | null = null;
    let isResolved = false;

    const cleanup = () => {
      if (!isResolved) {
        isResolved = true;
        socket.destroy();
      }
    };

    socket.setTimeout(timeoutMs);

    socket.connect(port, ip, () => {
      const latency = Date.now() - startTime;

      // Attempt quick non-destructive banner read
      if (port === 80 || port === 8080) {
        try {
          socket.write('HEAD / HTTP/1.0\r\nHost: target\r\n\r\n');
        } catch {
          // Ignore
        }
      }

      socket.once('data', (data) => {
        try {
          const text = data.toString('utf8', 0, 150).replace(/[^\x20-\x7E\r\n]/g, '').trim();
          banner = text.split('\n')[0].substring(0, 100);
        } catch {
          // Ignore
        }
        cleanup();
        resolve({ isOpen: true, latencyMs: latency, banner });
      });

      // If no banner within 250ms of connect, resolve open anyway
      setTimeout(() => {
        if (!isResolved) {
          cleanup();
          resolve({ isOpen: true, latencyMs: latency, banner });
        }
      }, 250);
    });

    socket.on('timeout', () => {
      cleanup();
      resolve({ isOpen: false, latencyMs: null, banner: null });
    });

    socket.on('error', () => {
      cleanup();
      resolve({ isOpen: false, latencyMs: null, banner: null });
    });
  });
}

export function evaluateOsSignature(openPorts: number[], banners: string[] = []): { osMatch: string; evidence: string } {
  const portSet = new Set(openPorts);

  for (const b of banners) {
    if (!b) continue;
    const lower = b.toLowerCase();
    if (lower.includes('ubuntu')) return { osMatch: 'Linux (Ubuntu)', evidence: `Banner: "${b.substring(0, 60)}"` };
    if (lower.includes('debian')) return { osMatch: 'Linux (Debian)', evidence: `Banner: "${b.substring(0, 60)}"` };
    if (lower.includes('microsoft') || lower.includes('iis')) return { osMatch: 'Microsoft Windows', evidence: `Banner: "${b.substring(0, 60)}"` };
    if (lower.includes('cisco')) return { osMatch: 'Cisco IOS', evidence: `Banner: "${b.substring(0, 60)}"` };
  }

  if (portSet.has(445) && (portSet.has(135) || portSet.has(3389))) {
    return { osMatch: 'Microsoft Windows', evidence: 'SMB (445) with MSRPC (135) or RDP (3389) active' };
  }
  if (portSet.has(22) && (portSet.has(80) || portSet.has(443)) && !portSet.has(445)) {
    return { osMatch: 'Linux / Unix', evidence: 'Standard POSIX stack with SSH (22) and Web; SMB absent' };
  }

  return { osMatch: 'Unknown', evidence: 'Insufficient port or banner signatures to determine OS reliably' };
}

export function generateCsvExport(report: ScanReport): string {
  const headers = ['IP Address', 'MAC Address', 'Vendor', 'Hostname', 'Open Ports', 'Estimated OS', 'Evidence', 'Latency (ms)'];
  const rows = report.discoveredDevices.map((d) => [
    `"${d.ipAddress}"`,
    `"${d.macAddress || 'N/A (L3 only)'}"`,
    `"${d.vendor || 'Unknown'}"`,
    `"${d.hostname || 'Unresolved'}"`,
    `"${d.openPorts.length > 0 ? d.openPorts.join(',') : 'None detected'}"`,
    `"${d.osMatch}"`,
    `"${(d.evidence || '').replace(/"/g, '""')}"`,
    `"${d.latencyMs !== null ? d.latencyMs : ''}"`,
  ]);

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
}
