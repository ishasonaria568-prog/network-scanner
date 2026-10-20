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

export interface AgentInfo {
  agent_id: string;
  agent_name: string;
  local_ip: string;
  hostname: string;
  platform: string;
  arp_supported: boolean;
  status: 'online' | 'busy' | 'offline';
  last_heartbeat: string;
}

export interface CapabilitiesResponse {
  deployment: 'vercel' | 'cloud_run' | 'node_server' | 'local_linux' | string;
  arp_discovery: boolean;
  raw_packet_access: boolean;
  external_agent_configured: boolean;
  supported_methods: string[];
  status: 'full' | 'limited';
  agent_info: AgentInfo | null;
  limitations: string[];
}
