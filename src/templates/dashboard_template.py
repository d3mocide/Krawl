#!/usr/bin/env python3

"""
Dashboard template for viewing honeypot statistics.
Customize this template to change the dashboard appearance.
"""

import html
from datetime import datetime

def _escape(value) -> str:
    """Escape HTML special characters to prevent XSS attacks."""
    if value is None:
        return ""
    return html.escape(str(value))

def format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp for display (YYYY-MM-DD HH:MM:SS)"""
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Fallback for old format
        return iso_timestamp.split("T")[1][:8] if "T" in iso_timestamp else iso_timestamp


def generate_dashboard(stats: dict) -> str:
    """Generate dashboard HTML with access statistics"""
    
    # Generate IP rows (IPs are generally safe but escape for consistency)
    top_ips_rows = '\n'.join([
        f'<tr><td class="rank">{i+1}</td><td>{_escape(ip)}</td><td>{count}</td></tr>'
        for i, (ip, count) in enumerate(stats['top_ips'])
    ]) or '<tr><td colspan="3" style="text-align:center;">No data</td></tr>'

    # Generate paths rows (CRITICAL: paths can contain XSS payloads)
    top_paths_rows = '\n'.join([
        f'<tr><td class="rank">{i+1}</td><td>{_escape(path)}</td><td>{count}</td></tr>'
        for i, (path, count) in enumerate(stats['top_paths'])
    ]) or '<tr><td colspan="3" style="text-align:center;">No data</td></tr>'

    # Generate User-Agent rows (CRITICAL: user agents can contain XSS payloads)
    top_ua_rows = '\n'.join([
        f'<tr><td class="rank">{i+1}</td><td style="word-break: break-all;">{_escape(ua[:80])}</td><td>{count}</td></tr>'
        for i, (ua, count) in enumerate(stats['top_user_agents'])
    ]) or '<tr><td colspan="3" style="text-align:center;">No data</td></tr>'

    # Generate suspicious accesses rows (CRITICAL: multiple user-controlled fields)
    suspicious_rows = '\n'.join([
        f'<tr><td>{_escape(log["ip"])}</td><td>{_escape(log["path"])}</td><td style="word-break: break-all;">{_escape(log["user_agent"][:60])}</td><td>{_escape(log["timestamp"].split("T")[1][:8])}</td></tr>'
        for log in stats['recent_suspicious'][-10:]
    ]) or '<tr><td colspan="4" style="text-align:center;">No suspicious activity detected</td></tr>'

    # Generate honeypot triggered IPs rows
    honeypot_rows = '\n'.join([
        f'<tr><td>{_escape(ip)}</td><td style="word-break: break-all;">{_escape(", ".join(paths))}</td><td>{len(paths)}</td></tr>'
        for ip, paths in stats.get('honeypot_triggered_ips', [])
    ]) or '<tr><td colspan="3" style="text-align:center;">No honeypot triggers yet</td></tr>'

    # Generate attack types rows (CRITICAL: paths and user agents are user-controlled)
    attack_type_rows = '\n'.join([
        f'<tr><td>{_escape(log["ip"])}</td><td>{_escape(log["path"])}</td><td>{_escape(", ".join(log["attack_types"]))}</td><td style="word-break: break-all;">{_escape(log["user_agent"][:60])}</td><td>{_escape(log["timestamp"].split("T")[1][:8])}</td></tr>'
        for log in stats.get('attack_types', [])[-10:]
    ]) or '<tr><td colspan="4" style="text-align:center;">No attacks detected</td></tr>'

    # Generate credential attempts rows (CRITICAL: usernames and passwords are user-controlled)
    credential_rows = '\n'.join([
        f'<tr><td>{_escape(log["ip"])}</td><td>{_escape(log["username"])}</td><td>{_escape(log["password"])}</td><td>{_escape(log["path"])}</td><td>{_escape(log["timestamp"].split("T")[1][:8])}</td></tr>'
        for log in stats.get('credential_attempts', [])[-20:]
    ]) or '<tr><td colspan="5" style="text-align:center;">No credentials captured yet</td></tr>'

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Krawl Dashboard</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        h1 {{
            color: #58a6ff;
            text-align: center;
            margin-bottom: 40px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card.alert {{
            border-color: #f85149;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            color: #58a6ff;
        }}
        .stat-value.alert {{
            color: #f85149;
        }}
        .stat-label {{
            font-size: 14px;
            color: #8b949e;
            margin-top: 5px;
        }}
        .table-container {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        h2 {{
            color: #58a6ff;
            margin-top: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }}
        th {{
            background: #0d1117;
            color: #58a6ff;
            font-weight: 600;
        }}
        tr:hover {{
            background: #1c2128;
        }}
        .rank {{
            color: #8b949e;
            font-weight: bold;
        }}
        .alert-section {{
            background: #1c1917;
            border-left: 4px solid #f85149;
        }}
        th.sortable {{
            cursor: pointer;
            user-select: none;
            position: relative;
            padding-right: 24px;
        }}
        th.sortable:hover {{
            background: #1c2128;
        }}
        th.sortable::after {{
            content: '⇅';
            position: absolute;
            right: 8px;
            opacity: 0.5;
            font-size: 12px;
        }}
        th.sortable.asc::after {{
            content: '▲';
            opacity: 1;
        }}
        th.sortable.desc::after {{
            content: '▼';
            opacity: 1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Krawl Dashboard</h1>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['total_accesses']}</div>
                <div class="stat-label">Total Accesses</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['unique_ips']}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['unique_paths']}</div>
                <div class="stat-label">Unique Paths</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-value alert">{stats['suspicious_accesses']}</div>
                <div class="stat-label">Suspicious Accesses</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-value alert">{stats.get('honeypot_ips', 0)}</div>
                <div class="stat-label">Honeypot Caught</div>
            </div>
            <div class="stat-card alert">
                <div class="stat-value alert">{len(stats.get('credential_attempts', []))}</div>
                <div class="stat-label">Credentials Captured</div>
            </div>
        </div>

        <div class="table-container alert-section">
            <h2>Honeypot Triggers by IP</h2>
            <table id="honeypot-table">
                <thead>
                    <tr>
                        <th class="sortable" data-sort="ip">IP Address</th>
                        <th>Accessed Paths</th>
                        <th class="sortable" data-sort="count">Count</th>
                    </tr>
                </thead>
                <tbody>
                    {honeypot_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container alert-section">
            <h2>Recent Suspicious Activity</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Path</th>
                        <th>User-Agent</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {suspicious_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container alert-section">
            <h2>Captured Credentials</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Path</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {credential_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container alert-section">
            <h2>Detected Attack Types</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Path</th>
                        <th>Attack Types</th>
                        <th>User-Agent</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {attack_type_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container">
            <h2>Top IP Addresses</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Access Count</th>
                    </tr>
                </thead>
                <tbody>
                    {top_ips_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container">
            <h2>Top Paths</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Path</th>
                        <th>Access Count</th>
                    </tr>
                </thead>
                <tbody>
                    {top_paths_rows}
                </tbody>
            </table>
        </div>

        <div class="table-container">
            <h2>Top User-Agents</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>User-Agent</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    {top_ua_rows}
                </tbody>
            </table>
        </div>
    </div>
    <script>
        // Add sorting functionality to tables
        document.querySelectorAll('th.sortable').forEach(header => {{
            header.addEventListener('click', function() {{
                const table = this.closest('table');
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const sortType = this.getAttribute('data-sort');
                const columnIndex = Array.from(this.parentElement.children).indexOf(this);
                
                // Determine sort direction
                const isAscending = this.classList.contains('asc');
                
                // Remove sort classes from all headers in this table
                table.querySelectorAll('th.sortable').forEach(th => {{
                    th.classList.remove('asc', 'desc');
                }});
                
                // Add appropriate class to clicked header
                this.classList.add(isAscending ? 'desc' : 'asc');
                
                // Sort rows
                rows.sort((a, b) => {{
                    let aValue = a.cells[columnIndex].textContent.trim();
                    let bValue = b.cells[columnIndex].textContent.trim();
                    
                    // Handle numeric sorting
                    if (sortType === 'count') {{
                        aValue = parseInt(aValue) || 0;
                        bValue = parseInt(bValue) || 0;
                        return isAscending ? bValue - aValue : aValue - bValue;
                    }}
                    
                    // Handle IP address sorting
                    if (sortType === 'ip') {{
                        const ipToNum = ip => {{
                            const parts = ip.split('.');
                            if (parts.length !== 4) return 0;
                            return parts.reduce((acc, part, i) => acc + (parseInt(part) || 0) * Math.pow(256, 3 - i), 0);
                        }};
                        const aNum = ipToNum(aValue);
                        const bNum = ipToNum(bValue);
                        return isAscending ? bNum - aNum : aNum - bNum;
                    }}
                    
                    // Default string sorting
                    if (isAscending) {{
                        return bValue.localeCompare(aValue);
                    }} else {{
                        return aValue.localeCompare(bValue);
                    }}
                }});
                
                // Re-append sorted rows
                rows.forEach(row => tbody.appendChild(row));
            }});
        }});
    </script>
</body>
</html>
"""
