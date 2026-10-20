/**
 * API Router for Network Scanner
 * Built by Isha Sonaria
 *
 * Implements REST endpoints for capabilities, scan orchestration,
 * agent communication, exports, and audit history.
 */

import express, { Request, Response } from 'express';
import { agentBridge } from './agentBridge';
import {
  COMMON_SERVICES,
  DiscoveredDevice,
  evaluateOsSignature,
  generateCsvExport,
  parsePortList,
  probeTcpPort,
  resolveReverseDns,
  ScanReport,
  validateTargetNetwork,
} from './scannerEngine';

export const apiRouter = express.Router();
apiRouter.use(express.json());

// 1. Capability Detection Endpoint
apiRouter.get('/capabilities', (req: Request, res: Response) => {
  const isVercel = Boolean(process.env.VERCEL || process.env.NOW_REGION);
  const isCloudRun = Boolean(process.env.K_SERVICE);
  const deployment = isVercel ? 'vercel' : isCloudRun ? 'cloud_run' : 'node_server';

  const agentOnline = agentBridge.isAgentOnline();
  const agent = agentBridge.getAgent();

  const supportedMethods = ['tcp_connect', 'hostname_resolution'];
  if (agentOnline && agent?.arpSupported) {
    supportedMethods.unshift('arp_discovery');
  }

  const limitations: string[] = [];
  if (isVercel) {
    limitations.push('Running on Vercel Serverless: Layer 2 ARP broadcasts and raw sockets are unsupported in cloud sandboxes.');
  }
  if (!agentOnline) {
    limitations.push('No External Scanner Agent is currently connected. Local ARP discovery is routed via the agent.');
  }

  res.json({
    deployment,
    arp_discovery: agentOnline && Boolean(agent?.arpSupported),
    raw_packet_access: false,
    external_agent_configured: agentOnline,
    supported_methods: supportedMethods,
    status: agentOnline ? 'full' : 'limited',
    agent_info: agent
      ? {
          agent_id: agent.agentId,
          agent_name: agent.agentName,
          status: agent.status,
          local_ip: agent.localIp,
          hostname: agent.hostname,
          platform: agent.platform,
          arp_supported: agent.arpSupported,
          last_heartbeat: agent.lastHeartbeat,
        }
      : null,
    limitations,
  });
});

// 2. Initiate New Scan
apiRouter.post('/scans', async (req: Request, res: Response) => {
  try {
    const { target, method = 'tcp_connect', ports, timeout = 1200, authorized = false } = req.body;

    // Strict Authorization Check
    if (!authorized) {
      return res.status(403).json({
        error: 'Authorization Required',
        message: 'You must explicitly confirm you own or have written permission to scan the target network.',
      });
    }

    if (!target) {
      return res.status(400).json({ error: 'Target network or IP is required.' });
    }

    // Input Validation & Host Enumeration
    let targetInfo;
    try {
      targetInfo = validateTargetNetwork(target, 256);
    } catch (valErr: any) {
      return res.status(400).json({ error: 'Validation Error', message: valErr.message });
    }

    const { network, hosts } = targetInfo;
    const portList = parsePortList(ports);

    // If method is ARP discovery:
    if (method === 'arp_discovery') {
      const isAgentUp = agentBridge.isAgentOnline();
      if (!isAgentUp) {
        return res.status(400).json({
          error: 'Agent Offline',
          message:
            'Layer 2 ARP broadcast scanning cannot execute directly inside Vercel/cloud serverless environments. ' +
            'Please start the External Scanner Agent on your Kali Linux/local machine to bridge ARP discovery.',
          remedy: 'Run: python3 -m agent.client --server-url <THIS_APP_URL> --token <AGENT_TOKEN>',
        });
      }

      // Queue scan job for the external agent
      const job = agentBridge.queueJob(network, 'arp_discovery', portList, timeout / 1000);
      return res.json({
        scan_id: job.jobId,
        target_network: network,
        scan_method: 'arp_discovery',
        status: 'pending',
        delegated_to_agent: true,
        message: 'Scan job successfully dispatched to connected external agent.',
      });
    }

    // If method is TCP Connect:
    // Execute real server-side TCP probes against permitted targets
    const scanId = 'scan-' + Date.now().toString(36) + '-' + Math.random().toString(36).substring(2, 6);
    const startTime = Date.now();
    const startedAt = new Date().toISOString();

    const discoveredDevices: DiscoveredDevice[] = [];
    const errors: string[] = [];

    // Probe hosts concurrently with bounded pool
    const concurrency = 20;
    const hostChunks: string[][] = [];
    for (let i = 0; i < hosts.length; i += concurrency) {
      hostChunks.push(hosts.slice(i, i + concurrency));
    }

    for (const chunk of hostChunks) {
      await Promise.all(
        chunk.map(async (ip) => {
          try {
            const openPortFindings = [];
            const latencies: number[] = [];
            const banners: string[] = [];

            for (const p of portList) {
              const probeRes = await probeTcpPort(ip, p, timeout);
              if (probeRes.isOpen) {
                if (probeRes.latencyMs !== null) latencies.push(probeRes.latencyMs);
                if (probeRes.banner) banners.push(probeRes.banner);
                openPortFindings.push({
                  port: p,
                  service: (COMMON_SERVICES as any)[p] || 'unknown',
                  state: 'open' as const,
                  banner: probeRes.banner,
                  responseTimeMs: probeRes.latencyMs,
                });
              }
            }

            if (openPortFindings.length > 0) {
              const hostname = await resolveReverseDns(ip);
              const avgLatency = latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : null;
              const { osMatch, evidence } = evaluateOsSignature(
                openPortFindings.map((f) => f.port),
                banners
              );

              discoveredDevices.push({
                ipAddress: ip,
                macAddress: null, // Remote Layer 3 TCP cannot determine physical MAC
                hostname,
                vendor: null,
                openPorts: openPortFindings.map((f) => f.port),
                portDetails: openPortFindings,
                osMatch,
                evidence,
                latencyMs: avgLatency,
              });
            }
          } catch (err: any) {
            errors.push(`Host ${ip}: ${err.message}`);
          }
        })
      );
    }

    const durationSeconds = Math.round((Date.now() - startTime) / 10) / 100;
    const completedAt = new Date().toISOString();

    const report: ScanReport = {
      scanId,
      targetNetwork: network,
      scanMethod: 'tcp_connect',
      startedAt,
      completedAt,
      status: errors.length > 0 && discoveredDevices.length === 0 ? 'failed' : errors.length > 0 ? 'partial' : 'completed',
      durationSeconds,
      totalHosts: hosts.length,
      discoveredDevices,
      errors,
    };

    agentBridge.saveScanReport(report);

    res.json(report);
  } catch (err: any) {
    res.status(500).json({ error: 'Scan Error', message: err.message });
  }
});

// 3. Retrieve Scan Status and Results
apiRouter.get('/scans/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const report = agentBridge.getScanReport(id);

  if (report) {
    return res.json(report);
  }

  return res.status(404).json({ error: 'Scan not found', scan_id: id });
});

// 4. Download Export (CSV or JSON)
apiRouter.get('/scans/:id/export', (req: Request, res: Response) => {
  const { id } = req.params;
  const format = req.query.format === 'csv' ? 'csv' : 'json';
  const report = agentBridge.getScanReport(id);

  if (!report) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  if (format === 'csv') {
    const csvData = generateCsvExport(report);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="scan_${id}.csv"`);
    return res.send(csvData);
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="scan_${id}.json"`);
  return res.json(report);
});

// 5. Scan History
apiRouter.get('/history', (req: Request, res: Response) => {
  const all = agentBridge.getAllScanReports();
  res.json({
    total: all.length,
    scans: all,
  });
});

// 6. External Agent: Register
apiRouter.post('/agent/register', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!agentBridge.validateToken(authHeader)) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or missing agent token.' });
  }

  const { agent_id, agent_name, local_ip, hostname, platform, arp_supported, raw_packet_access, is_root, allowed_subnets } = req.body;

  if (!agent_id) {
    return res.status(400).json({ error: 'agent_id is required' });
  }

  const agent = agentBridge.registerAgent({
    agentId: agent_id,
    agentName: agent_name || 'Agent',
    localIp: local_ip || 'unknown',
    hostname: hostname || 'unknown',
    platform: platform || 'unknown',
    arpSupported: Boolean(arp_supported),
    rawPacketAccess: Boolean(raw_packet_access),
    isRoot: Boolean(is_root),
    allowedSubnets: Array.isArray(allowed_subnets) ? allowed_subnets : [],
  });

  res.json({
    status: 'connected',
    agent_id: agent.agentId,
    message: 'Agent registered successfully. Ready to receive scan jobs.',
  });
});

// 7. External Agent: Status & Pairing Token
apiRouter.get('/agent/status', (req: Request, res: Response) => {
  const agent = agentBridge.getAgent();
  res.json({
    token: agentBridge.getAgentToken(),
    is_online: agentBridge.isAgentOnline(),
    agent: agent,
  });
});

// 8. External Agent: Regenerate Token
apiRouter.post('/agent/token/regenerate', (req: Request, res: Response) => {
  const newToken = agentBridge.regenerateAgentToken();
  res.json({ token: newToken });
});

// 9. External Agent: Poll for Pending Job
apiRouter.get('/agent/poll', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!agentBridge.validateToken(authHeader)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const agentId = String(req.query.agent_id || '');
  const job = agentBridge.pollNextJob(agentId);

  res.json({ job });
});

// 10. External Agent: Submit Scan Results
apiRouter.post('/agent/submit', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!agentBridge.validateToken(authHeader)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { job_id, target, method, status = 'completed', report, error } = req.body;
  if (!job_id || !target) {
    return res.status(400).json({ error: 'job_id and target are required' });
  }

  const savedReport = agentBridge.submitJobResult(job_id, target, method || 'arp_discovery', status, report, error);

  res.json({ status: 'received', scan_id: savedReport.scanId });
});
