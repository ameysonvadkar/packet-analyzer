// DPI Dashboard Backend
// Node.js WebSocket server + UDP bridge to C++ DPI engine.
//
// Architecture:
//   C++ Engine (UDP:5005/5006) <-> Node.js Backend (WS:3001) <-> React Frontend
//
// - Receives JSON stats from C++ engine on UDP port 5006
// - Sends control commands to C++ engine on UDP port 5005
// - Streams real-time data to React frontend via WebSocket on port 3001
// - Also serves a REST API for rule management

const dgram = require('dgram');
const http = require('http');
const { WebSocketServer } = require('ws');

const CONTROL_PORT = 5005;  // Send commands to C++ engine
const STATS_PORT = 5006;    // Receive stats from C++ engine
const WS_PORT = 3001;       // WebSocket server for frontend

// ============================================================================
// State
// ============================================================================
let latestStats = {
  total_packets: 0,
  total_bytes: 0,
  tcp_packets: 0,
  udp_packets: 0,
  forwarded: 0,
  dropped: 0,
  active_connections: 0,
  apps: {},
  domains: [],
  rules: { blocked_ips: 0, blocked_apps: 0, blocked_domains: 0, blocked_ports: 0 },
  fp_stats: [],
};

// Time-series data for charts (keep last 60 data points = 60 seconds)
const MAX_HISTORY = 60;
let statsHistory = [];
let alertLog = [];
const MAX_ALERTS = 100;

// Track previous values for rate calculation
let prevStats = { total_packets: 0, total_bytes: 0 };

// ============================================================================
// UDP Stats Receiver (from C++ engine)
// ============================================================================
const statsReceiver = dgram.createSocket('udp4');

statsReceiver.on('message', (msg) => {
  try {
    const data = JSON.parse(msg.toString());
    
    // Calculate rates
    const now = Date.now();
    const pps = data.total_packets - prevStats.total_packets;
    const bps = data.total_bytes - prevStats.total_bytes;
    
    prevStats = { total_packets: data.total_packets, total_bytes: data.total_bytes };
    
    latestStats = {
      ...data,
      pps,
      bps,
      timestamp: now,
    };
    
    // Add to history
    statsHistory.push({
      timestamp: now,
      pps,
      bps,
      forwarded: data.forwarded,
      dropped: data.dropped,
      total_packets: data.total_packets,
      active_connections: data.active_connections || 0,
    });
    
    if (statsHistory.length > MAX_HISTORY) {
      statsHistory.shift();
    }
    
    // Track new blocks as alerts
    if (data.dropped > (prevStats.dropped || 0)) {
      alertLog.push({
        timestamp: now,
        type: 'BLOCK',
        message: `Dropped ${data.dropped - (prevStats.dropped || 0)} packet(s)`,
      });
      if (alertLog.length > MAX_ALERTS) alertLog.shift();
    }
    
    // Broadcast to all connected WebSocket clients
    broadcastToClients({
      type: 'stats',
      data: latestStats,
      history: statsHistory,
    });
  } catch (e) {
    // Ignore parse errors
  }
});

statsReceiver.on('error', (err) => {
  console.error(`[Stats Receiver] Error: ${err.message}`);
});

statsReceiver.bind(STATS_PORT, '127.0.0.1', () => {
  console.log(`[Stats Receiver] Listening on UDP port ${STATS_PORT}`);
});

// ============================================================================
// UDP Command Sender (to C++ engine)
// ============================================================================
const commandSender = dgram.createSocket('udp4');

function sendCommand(command) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.from(command);
    commandSender.send(buf, 0, buf.length, CONTROL_PORT, '127.0.0.1', (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

// ============================================================================
// HTTP Server for REST API
// ============================================================================
const httpServer = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }
  
  const url = new URL(req.url, `http://localhost:${WS_PORT}`);
  
  // GET /api/stats - Get current stats
  if (req.method === 'GET' && url.pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      stats: latestStats,
      history: statsHistory,
      alerts: alertLog.slice(-20),
    }));
    return;
  }
  
  // POST /api/rules/block - Block something
  if (req.method === 'POST' && url.pathname === '/api/rules/block') {
    let body = '';
    req.on('data', (chunk) => body += chunk);
    req.on('end', async () => {
      try {
        const { type, value } = JSON.parse(body);
        let command = '';
        
        switch (type) {
          case 'ip': command = `BLOCK_IP ${value}`; break;
          case 'app': command = `BLOCK_APP ${value}`; break;
          case 'domain': command = `BLOCK_DOMAIN ${value}`; break;
          default:
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid type' }));
            return;
        }
        
        await sendCommand(command);
        
        alertLog.push({
          timestamp: Date.now(),
          type: 'RULE_ADD',
          message: `Blocked ${type}: ${value}`,
        });
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, command }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }
  
  // POST /api/rules/unblock - Unblock something
  if (req.method === 'POST' && url.pathname === '/api/rules/unblock') {
    let body = '';
    req.on('data', (chunk) => body += chunk);
    req.on('end', async () => {
      try {
        const { type, value } = JSON.parse(body);
        let command = '';
        
        switch (type) {
          case 'ip': command = `UNBLOCK_IP ${value}`; break;
          case 'app': command = `UNBLOCK_APP ${value}`; break;
          case 'domain': command = `UNBLOCK_DOMAIN ${value}`; break;
          default:
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid type' }));
            return;
        }
        
        await sendCommand(command);
        
        alertLog.push({
          timestamp: Date.now(),
          type: 'RULE_REMOVE',
          message: `Unblocked ${type}: ${value}`,
        });
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, command }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }
  
  // GET /api/alerts - Get recent alerts
  if (req.method === 'GET' && url.pathname === '/api/alerts') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(alertLog.slice(-50)));
    return;
  }
  
  // Default 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

// ============================================================================
// WebSocket Server (for real-time frontend streaming)
// ============================================================================
const wss = new WebSocketServer({ server: httpServer });
const clients = new Set();

wss.on('connection', (ws) => {
  clients.add(ws);
  console.log(`[WebSocket] Client connected (total: ${clients.size})`);
  
  // Send current state immediately
  ws.send(JSON.stringify({
    type: 'init',
    data: latestStats,
    history: statsHistory,
    alerts: alertLog.slice(-20),
  }));
  
  ws.on('message', async (message) => {
    try {
      const msg = JSON.parse(message);
      
      if (msg.type === 'command') {
        await sendCommand(msg.command);
        ws.send(JSON.stringify({ type: 'command_ack', command: msg.command }));
      }
    } catch (e) {
      ws.send(JSON.stringify({ type: 'error', message: e.message }));
    }
  });
  
  ws.on('close', () => {
    clients.delete(ws);
    console.log(`[WebSocket] Client disconnected (total: ${clients.size})`);
  });
});

function broadcastToClients(data) {
  const msg = JSON.stringify(data);
  for (const client of clients) {
    if (client.readyState === 1) {  // OPEN
      client.send(msg);
    }
  }
}

// ============================================================================
// Demo mode: generate fake stats when no C++ engine is running
// ============================================================================
let demoInterval = null;
let demoPacketCount = 0;
let demoByteCount = 0;

function startDemoMode() {
  console.log('[Demo] Starting demo mode (simulated data)...');
  
  const apps = ['YouTube', 'Google', 'Facebook', 'Netflix', 'HTTPS', 'DNS', 'Instagram', 'Twitter/X'];
  
  demoInterval = setInterval(() => {
    const pps = Math.floor(Math.random() * 500) + 100;
    const bps = pps * (Math.floor(Math.random() * 800) + 200);
    demoPacketCount += pps;
    demoByteCount += bps;
    
    const dropped = Math.floor(Math.random() * 20);
    
    const appDist = {};
    apps.forEach(app => {
      appDist[app] = Math.floor(Math.random() * 50) + 5;
    });
    
    const fakeStats = {
      total_packets: demoPacketCount,
      total_bytes: demoByteCount,
      tcp_packets: Math.floor(demoPacketCount * 0.85),
      udp_packets: Math.floor(demoPacketCount * 0.15),
      forwarded: demoPacketCount - dropped * 10,
      dropped: dropped * 10,
      active_connections: Math.floor(Math.random() * 200) + 50,
      pps,
      bps,
      apps: appDist,
      domains: [
        { domain: 'www.youtube.com', app: 'YouTube' },
        { domain: 'www.google.com', app: 'Google' },
        { domain: 'www.facebook.com', app: 'Facebook' },
        { domain: 'www.netflix.com', app: 'Netflix' },
      ],
      rules: { blocked_ips: 2, blocked_apps: 1, blocked_domains: 3, blocked_ports: 0 },
      fp_stats: [
        { id: 0, processed: Math.floor(demoPacketCount / 4), forwarded: Math.floor(demoPacketCount / 4) - 5, dropped: 5, connections: 45 },
        { id: 1, processed: Math.floor(demoPacketCount / 4), forwarded: Math.floor(demoPacketCount / 4) - 3, dropped: 3, connections: 52 },
        { id: 2, processed: Math.floor(demoPacketCount / 4), forwarded: Math.floor(demoPacketCount / 4) - 7, dropped: 7, connections: 48 },
        { id: 3, processed: Math.floor(demoPacketCount / 4), forwarded: Math.floor(demoPacketCount / 4) - 5, dropped: 5, connections: 55 },
      ],
      timestamp: Date.now(),
    };
    
    latestStats = fakeStats;
    
    statsHistory.push({
      timestamp: Date.now(),
      pps,
      bps,
      forwarded: fakeStats.forwarded,
      dropped: fakeStats.dropped,
      total_packets: fakeStats.total_packets,
      active_connections: fakeStats.active_connections,
    });
    
    if (statsHistory.length > MAX_HISTORY) statsHistory.shift();
    
    broadcastToClients({
      type: 'stats',
      data: latestStats,
      history: statsHistory,
    });
  }, 1000);
}

// ============================================================================
// Start
// ============================================================================
httpServer.listen(WS_PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║              DPI Dashboard Backend v1.0                     ║
╠══════════════════════════════════════════════════════════════╣
║  HTTP/WebSocket: http://localhost:${WS_PORT}                     ║
║  UDP Stats In:   port ${STATS_PORT} (from C++ engine)              ║
║  UDP Control Out:port ${CONTROL_PORT} (to C++ engine)                ║
╚══════════════════════════════════════════════════════════════╝
  `);
  
  // Start demo mode by default (real stats will override when C++ engine connects)
  startDemoMode();
});
