import { useState, useEffect, useRef, useCallback } from 'react'
import './App.css'

const WS_URL = 'ws://localhost:3001'
const API_URL = 'http://localhost:3001/api'

// Utility: format bytes to human readable
function formatBytes(bytes) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

function formatTime(ts) {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-US', { hour12: false })
}

// App color map
const APP_COLORS = {
  'YouTube': 'app-youtube',
  'Google': 'app-google',
  'Facebook': 'app-facebook',
  'Netflix': 'app-netflix',
  'HTTPS': 'app-https',
  'DNS': 'app-dns',
  'Instagram': 'app-instagram',
  'Twitter/X': 'app-twitter',
}

function App() {
  const [connected, setConnected] = useState(false)
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const [alerts, setAlerts] = useState([])
  const wsRef = useRef(null)
  
  // Rule form state
  const [ruleType, setRuleType] = useState('ip')
  const [ruleValue, setRuleValue] = useState('')
  
  // Connect to WebSocket
  useEffect(() => {
    let ws = null
    let reconnectTimer = null
    
    function connect() {
      ws = new WebSocket(WS_URL)
      wsRef.current = ws
      
      ws.onopen = () => {
        setConnected(true)
        console.log('[WS] Connected')
      }
      
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          
          if (msg.type === 'init' || msg.type === 'stats') {
            setStats(msg.data)
            if (msg.history) setHistory(msg.history)
            if (msg.alerts) setAlerts(prev => {
              const newAlerts = [...prev, ...(msg.alerts || [])]
              return newAlerts.slice(-50)
            })
          }
        } catch (e) {
          // ignore
        }
      }
      
      ws.onclose = () => {
        setConnected(false)
        reconnectTimer = setTimeout(connect, 2000)
      }
      
      ws.onerror = () => {
        ws.close()
      }
    }
    
    connect()
    
    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (ws) ws.close()
    }
  }, [])
  
  // Block rule handler
  const handleBlock = useCallback(async () => {
    if (!ruleValue.trim()) return
    
    try {
      await fetch(`${API_URL}/rules/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: ruleType, value: ruleValue.trim() }),
      })
      
      setAlerts(prev => [...prev, {
        timestamp: Date.now(),
        type: 'RULE_ADD',
        message: `Blocked ${ruleType}: ${ruleValue.trim()}`,
      }].slice(-50))
      
      setRuleValue('')
    } catch (e) {
      console.error('Block failed:', e)
    }
  }, [ruleType, ruleValue])
  
  // Unblock rule handler
  const handleUnblock = useCallback(async () => {
    if (!ruleValue.trim()) return
    
    try {
      await fetch(`${API_URL}/rules/unblock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: ruleType, value: ruleValue.trim() }),
      })
      
      setAlerts(prev => [...prev, {
        timestamp: Date.now(),
        type: 'RULE_REMOVE',
        message: `Unblocked ${ruleType}: ${ruleValue.trim()}`,
      }].slice(-50))
      
      setRuleValue('')
    } catch (e) {
      console.error('Unblock failed:', e)
    }
  }, [ruleType, ruleValue])
  
  // Compute chart max for scaling
  const chartMax = Math.max(...history.map(h => h.pps || 0), 1)
  
  // Compute app distribution sorted
  const appEntries = stats?.apps
    ? Object.entries(stats.apps).sort((a, b) => b[1] - a[1])
    : []
  const appMax = appEntries.length > 0 ? appEntries[0][1] : 1
  
  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <div className="logo-icon">🛡️</div>
          <div>
            <h1>DPI Engine Dashboard</h1>
            <span className="header-subtitle">Deep Packet Inspection • Real-Time Monitor</span>
          </div>
        </div>
        <div className={`connection-status ${connected ? 'connected' : 'disconnected'}`}>
          <span className="status-dot"></span>
          {connected ? 'Connected' : 'Disconnected'}
        </div>
      </header>
      
      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card indigo">
          <div className="stat-label">Total Packets</div>
          <div className="stat-value">
            {formatNumber(stats?.total_packets || 0)}
          </div>
        </div>
        <div className="stat-card cyan">
          <div className="stat-label">Throughput</div>
          <div className="stat-value">
            {formatNumber(stats?.pps || 0)}
            <span className="stat-unit">pps</span>
          </div>
        </div>
        <div className="stat-card green">
          <div className="stat-label">Forwarded</div>
          <div className="stat-value">
            {formatNumber(stats?.forwarded || 0)}
          </div>
        </div>
        <div className="stat-card red">
          <div className="stat-label">Dropped</div>
          <div className="stat-value">
            {formatNumber(stats?.dropped || 0)}
          </div>
        </div>
        <div className="stat-card purple">
          <div className="stat-label">Active Connections</div>
          <div className="stat-value">
            {formatNumber(stats?.active_connections || 0)}
          </div>
        </div>
        <div className="stat-card orange">
          <div className="stat-label">Bandwidth</div>
          <div className="stat-value">
            {formatBytes(stats?.bps || 0)}
            <span className="stat-unit">/s</span>
          </div>
        </div>
      </div>
      
      {/* Main Grid */}
      <div className="main-grid">
        {/* Live Throughput Chart */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">
              📊 Live Throughput
              <span className="panel-badge">60s window</span>
            </span>
          </div>
          <div className="chart-container">
            {history.map((h, i) => (
              <div
                key={i}
                className="chart-bar"
                style={{ height: `${Math.max((h.pps / chartMax) * 100, 1)}%` }}
                title={`${h.pps} pps at ${formatTime(h.timestamp)}`}
              />
            ))}
            {history.length === 0 && (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Waiting for data...
              </div>
            )}
          </div>
          <div className="chart-labels">
            <span>{history.length > 0 ? formatTime(history[0]?.timestamp) : '--:--:--'}</span>
            <span>Packets per Second</span>
            <span>{history.length > 0 ? formatTime(history[history.length - 1]?.timestamp) : '--:--:--'}</span>
          </div>
        </div>
        
        {/* App Distribution */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">🌐 Application Distribution</span>
          </div>
          <div className="app-list">
            {appEntries.map(([app, count]) => (
              <div className="app-row" key={app}>
                <span className="app-name">{app}</span>
                <div className="app-bar-track">
                  <div
                    className={`app-bar-fill ${APP_COLORS[app] || 'app-default'}`}
                    style={{ width: `${(count / appMax) * 100}%` }}
                  >
                    {count > appMax * 0.15 ? count : ''}
                  </div>
                </div>
                <span className="app-count">{count}</span>
              </div>
            ))}
            {appEntries.length === 0 && (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '20px 0' }}>
                No app data yet
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* Bottom Grid */}
      <div className="bottom-grid">
        {/* Domains / Flow Table */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">🔗 Detected Domains</span>
            <span className="panel-badge">{stats?.domains?.length || 0}</span>
          </div>
          <div className="flow-table-container" style={{ maxHeight: '300px', overflowY: 'auto' }}>
            <table className="flow-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>App</th>
                </tr>
              </thead>
              <tbody>
                {(stats?.domains || []).map((d, i) => (
                  <tr key={i}>
                    <td>{d.domain}</td>
                    <td><span className="badge badge-app">{d.app}</span></td>
                  </tr>
                ))}
                {(!stats?.domains || stats.domains.length === 0) && (
                  <tr>
                    <td colSpan={2} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                      No domains detected
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
        
        {/* Rule Controller */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">⚙️ Rule Controller</span>
          </div>
          <div className="rule-form">
            <div className="form-group">
              <label className="form-label">Rule Type</label>
              <select
                className="form-select"
                value={ruleType}
                onChange={e => setRuleType(e.target.value)}
              >
                <option value="ip">IP Address</option>
                <option value="app">Application</option>
                <option value="domain">Domain</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">
                {ruleType === 'ip' ? 'IP Address' : ruleType === 'app' ? 'App Name' : 'Domain'}
              </label>
              <input
                className="form-input"
                type="text"
                placeholder={
                  ruleType === 'ip' ? '192.168.1.100' :
                  ruleType === 'app' ? 'YouTube' :
                  '*.tiktok.com'
                }
                value={ruleValue}
                onChange={e => setRuleValue(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleBlock()}
              />
            </div>
            <div className="btn-row">
              <button className="btn btn-block" onClick={handleBlock} style={{ flex: 1 }}>
                🚫 Block
              </button>
              <button className="btn btn-unblock" onClick={handleUnblock} style={{ flex: 1 }}>
                ✅ Unblock
              </button>
            </div>
            
            {/* Active rules summary */}
            {stats?.rules && (
              <div style={{ marginTop: '12px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span>Blocked IPs</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-red)' }}>{stats.rules.blocked_ips}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span>Blocked Apps</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-orange)' }}>{stats.rules.blocked_apps}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>Blocked Domains</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-purple)' }}>{stats.rules.blocked_domains}</span>
                </div>
              </div>
            )}
          </div>
        </div>
        
        {/* Alert Console */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">🚨 Alert Console</span>
            <span className="panel-badge">{alerts.length}</span>
          </div>
          <div className="alert-console">
            {alerts.slice(-15).reverse().map((alert, i) => (
              <div
                key={i}
                className={`alert-item ${
                  alert.type === 'BLOCK' ? 'block' :
                  alert.type === 'RULE_ADD' ? 'rule-add' :
                  alert.type === 'RULE_REMOVE' ? 'rule-remove' : ''
                }`}
              >
                <span className="alert-time">
                  {formatTime(alert.timestamp)}
                </span>
                <span className="alert-message">{alert.message}</span>
              </div>
            ))}
            {alerts.length === 0 && (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', padding: '20px 0' }}>
                No alerts yet
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* FastPath Distribution */}
      {stats?.fp_stats && stats.fp_stats.length > 0 && (
        <div className="panel" style={{ marginTop: '24px' }}>
          <div className="panel-header">
            <span className="panel-title">⚡ FastPath Thread Distribution</span>
            <span className="panel-badge">Direct Dispatch</span>
          </div>
          <div className="fp-grid">
            {stats.fp_stats.map(fp => (
              <div className="fp-card" key={fp.id}>
                <div className="fp-id">FP {fp.id}</div>
                <div className="fp-value">{formatNumber(fp.processed)}</div>
                <div className="fp-label">processed</div>
                <div style={{ marginTop: '6px', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  {fp.connections} conns
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default App
