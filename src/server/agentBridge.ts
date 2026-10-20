/**
 * Agent Bridge & Scan Store
 * Built by Isha Sonaria
 *
 * Coordinates external scanner agents running on Kali Linux or local LAN,
 * queues authorized scan jobs, validates agent tokens, and maintains real scan history.
 */

import { DiscoveredDevice, ScanReport } from './scannerEngine';

export interface AgentInfo {
  agentId: string;
  agentName: string;
  localIp: string;
  hostname: string;
  platform: string;
  arpSupported: boolean;
  rawPacketAccess: boolean;
  isRoot: boolean;
  allowedSubnets: string[];
  registeredAt: string;
  lastHeartbeat: string;
  status: 'online' | 'busy' | 'offline';
}

export interface QueuedScanJob {
  jobId: string;
  target: string;
  method: 'arp_discovery' | 'tcp_connect';
  ports: number[];
  timeout: number;
  status: 'pending' | 'dispatched' | 'completed' | 'failed';
  createdAt: string;
  dispatchedAt?: string;
  completedAt?: string;
}

class AgentBridge {
  private agent: AgentInfo | null = null;
  private agentToken: string = process.env.SCANNER_AGENT_TOKEN || 'edge-sec-token-' + Math.random().toString(36).substring(2, 10);
  private jobQueue: QueuedScanJob[] = [];
  private scanReports: Map<string, ScanReport> = new Map();

  // Heartbeat timeout in ms (agent marked offline if no ping in 20 seconds)
  private readonly HEARTBEAT_TIMEOUT_MS = 20000;

  getAgentToken(): string {
    return this.agentToken;
  }

  regenerateAgentToken(): string {
    this.agentToken = 'edge-sec-token-' + Math.random().toString(36).substring(2, 10);
    return this.agentToken;
  }

  validateToken(providedToken?: string): boolean {
    if (!this.agentToken) return true;
    if (!providedToken) return false;
    const clean = providedToken.replace(/^Bearer\s+/i, '').trim();
    return clean === this.agentToken;
  }

  registerAgent(info: Omit<AgentInfo, 'registeredAt' | 'lastHeartbeat' | 'status'>): AgentInfo {
    const now = new Date().toISOString();
    this.agent = {
      ...info,
      registeredAt: this.agent?.registeredAt || now,
      lastHeartbeat: now,
      status: 'online',
    };
    return this.agent;
  }

  getAgent(): AgentInfo | null {
    if (!this.agent) return null;
    const diff = Date.now() - new Date(this.agent.lastHeartbeat).getTime();
    if (diff > this.HEARTBEAT_TIMEOUT_MS) {
      this.agent.status = 'offline';
    }
    return this.agent;
  }

  isAgentOnline(): boolean {
    const ag = this.getAgent();
    return !!ag && ag.status === 'online';
  }

  queueJob(target: string, method: 'arp_discovery' | 'tcp_connect', ports: number[], timeout: number): QueuedScanJob {
    const job: QueuedScanJob = {
      jobId: 'job-' + Date.now().toString(36) + '-' + Math.random().toString(36).substring(2, 7),
      target,
      method,
      ports,
      timeout,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };
    this.jobQueue.push(job);
    return job;
  }

  pollNextJob(agentId: string): QueuedScanJob | null {
    if (this.agent && this.agent.agentId === agentId) {
      this.agent.lastHeartbeat = new Date().toISOString();
      this.agent.status = 'online';
    }

    const pending = this.jobQueue.find((j) => j.status === 'pending');
    if (pending) {
      pending.status = 'dispatched';
      pending.dispatchedAt = new Date().toISOString();
      if (this.agent) this.agent.status = 'busy';
      return pending;
    }
    return null;
  }

  submitJobResult(
    jobId: string,
    target: string,
    method: 'arp_discovery' | 'tcp_connect',
    status: 'completed' | 'failed' | 'partial',
    reportData?: Partial<ScanReport>,
    error?: string
  ): ScanReport {
    const now = new Date().toISOString();
    const existingJob = this.jobQueue.find((j) => j.jobId === jobId);
    if (existingJob) {
      existingJob.status = status === 'completed' ? 'completed' : 'failed';
      existingJob.completedAt = now;
    }

    if (this.agent) {
      this.agent.lastHeartbeat = now;
      this.agent.status = 'online';
    }

    const fullReport: ScanReport = {
      scanId: jobId,
      targetNetwork: target,
      scanMethod: method,
      startedAt: reportData?.startedAt || existingJob?.createdAt || now,
      completedAt: reportData?.completedAt || now,
      status: status,
      durationSeconds: reportData?.durationSeconds ?? 0,
      totalHosts: reportData?.totalHosts ?? 0,
      discoveredDevices: (reportData?.discoveredDevices as DiscoveredDevice[]) || [],
      errors: error ? [error, ...(reportData?.errors || [])] : (reportData?.errors || []),
    };

    this.scanReports.set(jobId, fullReport);
    return fullReport;
  }

  saveScanReport(report: ScanReport): void {
    this.scanReports.set(report.scanId, report);
  }

  getScanReport(scanId: string): ScanReport | undefined {
    return this.scanReports.get(scanId);
  }

  getAllScanReports(): ScanReport[] {
    return Array.from(this.scanReports.values()).sort(
      (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
    );
  }
}

export const agentBridge = new AgentBridge();
