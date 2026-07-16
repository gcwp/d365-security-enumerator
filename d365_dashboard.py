#!/usr/bin/env python3
"""Local, read-only dashboard for Dynamics 365 enumeration JSON.

The server binds to 127.0.0.1 only and reloads the JSON file whenever the page
requests data, so rerunning the enumerator and refreshing the browser is enough.

Usage:
    python d365_dashboard.py --input d365_enum.json
    python d365_dashboard.py --input results/client.json --port 8765
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>D365 Enumeration Dashboard</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0d1117;
      --panel: #161b22;
      --panel-2: #1d2430;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #58a6ff;
      --accent-2: #a371f7;
      --good: #3fb950;
      --warn: #d29922;
      --bad: #f85149;
      --neutral: #8b949e;
      --chip: #21262d;
      --shadow: 0 12px 36px rgba(0,0,0,.28);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    button, input, select { font: inherit; }
    .app { min-height: 100vh; }
    header {
      position: sticky;
      top: 0;
      z-index: 20;
      background: rgba(13,17,23,.94);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
    }
    .header-inner {
      max-width: 1600px;
      margin: 0 auto;
      padding: 18px 24px 12px;
    }
    .title-row {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
    }
    h1 { margin: 0; font-size: 22px; letter-spacing: .2px; }
    .subtitle { margin-top: 5px; color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }
    .local-badge {
      background: #12261a;
      border: 1px solid #276738;
      color: #7ee787;
      padding: 6px 9px;
      border-radius: 999px;
      font-size: 12px;
      white-space: nowrap;
    }
    nav {
      display: flex;
      gap: 6px;
      margin-top: 16px;
      overflow-x: auto;
      padding-bottom: 2px;
    }
    nav button {
      border: 1px solid transparent;
      color: var(--muted);
      background: transparent;
      padding: 8px 12px;
      border-radius: 8px;
      cursor: pointer;
      white-space: nowrap;
    }
    nav button:hover { color: var(--text); background: var(--panel); }
    nav button.active { color: var(--text); background: var(--panel-2); border-color: var(--border); }
    main { max-width: 1600px; margin: 0 auto; padding: 24px; }
    .notice {
      border: 1px solid #5f4b20;
      background: #2b2414;
      color: #e3b341;
      padding: 11px 13px;
      border-radius: 9px;
      margin-bottom: 18px;
      font-size: 13px;
    }
    .error-box {
      border: 1px solid #7d302d;
      background: #2f1618;
      color: #ffb3ad;
      padding: 14px;
      border-radius: 9px;
      white-space: pre-wrap;
    }
    .tab { display: none; }
    .tab.active { display: block; }
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 22px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      box-shadow: var(--shadow);
    }
    .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .65px; }
    .card .value { margin-top: 7px; font-size: 24px; font-weight: 700; }
    .card .small-value { margin-top: 7px; font-size: 15px; font-weight: 600; overflow-wrap: anywhere; }
    .section {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 18px;
      overflow: hidden;
    }
    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
    }
    .section-header h2, .section-header h3 { margin: 0; font-size: 16px; }
    .section-body { padding: 16px; }
    .muted { color: var(--muted); }
    .small { font-size: 12px; }
    .grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
    .filters {
      display: flex;
      flex-wrap: wrap;
      gap: 9px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      background: rgba(255,255,255,.015);
    }
    .filters input, .filters select {
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 10px;
      min-width: 150px;
    }
    .filters input { min-width: 260px; flex: 1; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th {
      text-align: left;
      color: var(--muted);
      font-weight: 600;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      background: #141920;
      position: sticky;
      top: 0;
      z-index: 2;
    }
    td { padding: 11px 12px; border-bottom: 1px solid #262c33; vertical-align: top; }
    tr:hover td { background: rgba(88,166,255,.035); }
    tr:last-child td { border-bottom: none; }
    .entity-name, .priv-name { font-weight: 650; }
    .chips { display: flex; gap: 5px; flex-wrap: wrap; }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 7px;
      border: 1px solid var(--border);
      background: var(--chip);
      color: #c9d1d9;
      border-radius: 999px;
      font-size: 11px;
      white-space: nowrap;
    }
    .chip.global { border-color: #6e40c9; color: #d2a8ff; }
    .chip.deep { border-color: #1f6feb; color: #79c0ff; }
    .chip.local { border-color: #238636; color: #7ee787; }
    .chip.basic { border-color: #9e6a03; color: #e3b341; }
    .status {
      display: inline-flex;
      align-items: center;
      padding: 4px 7px;
      border-radius: 999px;
      border: 1px solid var(--border);
      font-size: 11px;
      white-space: nowrap;
    }
    .status.data { color: #7ee787; border-color: #276738; background: #12261a; }
    .status.empty { color: #e3b341; border-color: #6e5a20; background: #2b2414; }
    .status.denied { color: #ff7b72; border-color: #7d302d; background: #2f1618; }
    .status.other { color: #a5d6ff; border-color: #31546f; background: #142534; }
    .open-link {
      display: inline-block;
      border: 1px solid #1f6feb;
      border-radius: 7px;
      padding: 5px 8px;
      white-space: nowrap;
    }
    details { border: 1px solid var(--border); border-radius: 8px; background: #11161d; }
    details + details { margin-top: 8px; }
    summary { cursor: pointer; padding: 9px 11px; color: #c9d1d9; }
    details pre { margin: 0; border-top: 1px solid var(--border); padding: 12px; overflow: auto; max-height: 500px; }
    pre {
      background: #0b0f14;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      color: #c9d1d9;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font-size: 12px;
    }
    .kv { display: grid; grid-template-columns: minmax(180px, 280px) 1fr; gap: 1px; background: var(--border); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
    .kv div { background: #11161d; padding: 8px 10px; overflow-wrap: anywhere; }
    .kv .key { color: var(--muted); }
    .signal { border-left: 3px solid var(--warn); padding: 9px 11px; background: #15191f; margin-bottom: 8px; }
    .signal-title { font-weight: 650; }
    .signal-meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
    .toolbar-count { color: var(--muted); font-size: 12px; }
    .empty-state { color: var(--muted); padding: 20px; text-align: center; }
    .raw-actions { display: flex; gap: 8px; margin-bottom: 10px; }
    .action-button {
      color: var(--text);
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 7px 10px;
      cursor: pointer;
    }
    .action-button:hover { border-color: var(--accent); }
    @media (max-width: 800px) {
      main, .header-inner { padding-left: 12px; padding-right: 12px; }
      .grid-2 { grid-template-columns: 1fr; }
      .title-row { flex-direction: column; }
      .kv { grid-template-columns: 1fr; }
      .kv .key { border-bottom: 1px solid var(--border); }
    }
  </style>
</head>
<body>
<div class="app">
  <header>
    <div class="header-inner">
      <div class="title-row">
        <div>
          <h1>Dynamics 365 Enumeration Dashboard</h1>
          <div id="subtitle" class="subtitle">Loading enumeration data…</div>
        </div>
        <div class="local-badge">Localhost only</div>
      </div>
      <nav id="tabs">
        <button data-tab="overview" class="active">Overview</button>
        <button data-tab="organization">Organization settings</button>
        <button data-tab="privileges">Privileges</button>
        <button data-tab="secrets">Secrets &amp; configuration</button>
        <button data-tab="standard">Default entities</button>
        <button data-tab="custom">Custom entities</button>
        <button data-tab="errors">Errors & raw</button>
      </nav>
    </div>
  </header>
  <main>
    <div class="notice">This viewer may display secrets and sensitive records found during the assessment. It is bound to 127.0.0.1 and does not send data elsewhere.</div>
    <div id="loadError" class="error-box" style="display:none"></div>
    <section id="tab-overview" class="tab active"></section>
    <section id="tab-organization" class="tab"></section>
    <section id="tab-privileges" class="tab"></section>
    <section id="tab-secrets" class="tab"></section>
    <section id="tab-standard" class="tab"></section>
    <section id="tab-custom" class="tab"></section>
    <section id="tab-errors" class="tab"></section>
  </main>
</div>
<script>
'use strict';
let DATA = null;

const escapeHtml = (value) => String(value ?? '')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
const j = (value) => JSON.stringify(value, null, 2);
const asArray = (value) => Array.isArray(value) ? value : [];
const asObject = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const path = (root, ...parts) => parts.reduce((value, key) => value && value[key] !== undefined ? value[key] : undefined, root);

function activateTab(name) {
  document.querySelectorAll('nav button').forEach(button => button.classList.toggle('active', button.dataset.tab === name));
  document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.id === `tab-${name}`));
}
document.getElementById('tabs').addEventListener('click', event => {
  const button = event.target.closest('button[data-tab]');
  if (button) activateTab(button.dataset.tab);
});

function statusInfo(status) {
  const mapping = {
    READABLE_WITH_DATA: ['Access with data', 'data'],
    READABLE_EMPTY_OR_FILTERED: ['Access, no visible data', 'empty'],
    ACCESS_DENIED: ['Access denied', 'denied'],
  };
  return mapping[status] || [status || 'Unknown', 'other'];
}

function chip(label, depth='') {
  return `<span class="chip ${escapeHtml(String(depth).toLowerCase())}">${escapeHtml(label)}</span>`;
}

function sourceLabels(sources) {
  const labels = [];
  asArray(sources).forEach(source => {
    const role = source.role_name || source.name || source.role_id || 'Unknown role';
    const assignments = asArray(source.assignments);
    if (!assignments.length) {
      labels.push(role);
      return;
    }
    assignments.forEach(assignment => {
      if (assignment.type === 'team' && assignment.team) labels.push(`${role} via ${assignment.team.name || assignment.team.team_id || 'team'}`);
      else labels.push(`${role} (${assignment.type || 'assignment'})`);
    });
  });
  return [...new Set(labels)];
}

function heldPrivilegeChips(entity) {
  const order = ['Create','Read','Write','Delete','Assign','Share','Append','AppendTo'];
  const privileges = asObject(entity.privileges);
  return order.flatMap(name => {
    const item = asObject(privileges[name]);
    return item.held === true ? [chip(`${name}: ${item.depth || 'held'}`, item.depth)] : [];
  }).join(' ');
}

function overviewCards() {
  const target = asObject(DATA.target);
  const identity = asObject(DATA.identity);
  const security = asObject(DATA.security);
  const inventory = asObject(security.privilege_inventory);
  const summary = asObject(inventory.summary);
  const access = asObject(DATA.entity_access || DATA.custom_entities);
  const counts = asObject(access.probe_status_counts);
  return `
    <div class="cards">
      <div class="card"><div class="label">Organization</div><div class="small-value">${escapeHtml(target.organization_name || path(DATA,'organization','name') || 'Unknown')}</div></div>
      <div class="card"><div class="label">API version</div><div class="value">${escapeHtml(target.api_version || '—')}</div></div>
      <div class="card"><div class="label">Held privileges</div><div class="value">${escapeHtml(summary.held_count ?? path(security,'reported_user_privileges','privilege_count') ?? 0)}</div></div>
      <div class="card"><div class="label">Custom entities</div><div class="value">${escapeHtml(access.custom_entity_count ?? 0)}</div></div>
      <div class="card"><div class="label">Default entities</div><div class="value">${escapeHtml(access.sensitive_standard_entity_count ?? 0)}</div></div>
      <div class="card"><div class="label">Readable with data</div><div class="value">${escapeHtml(counts.READABLE_WITH_DATA ?? 0)}</div></div>
      <div class="card"><div class="label">Access denied</div><div class="value">${escapeHtml(counts.ACCESS_DENIED ?? 0)}</div></div>
      <div class="card"><div class="label">Secret/config flags</div><div class="value">${escapeHtml(path(DATA,'secret_scan','finding_count') ?? 0)}</div></div>
      <div class="card"><div class="label">User ID</div><div class="small-value">${escapeHtml(identity.UserId || '—')}</div></div>
    </div>`;
}

function renderOverview() {
  const target = asObject(DATA.target);
  const organization = asObject(DATA.organization);
  const security = asObject(DATA.security);
  const access = asObject(DATA.entity_access || DATA.custom_entities);
  const depthCounts = asObject(path(security,'privilege_inventory','summary','depth_counts'));
  const signals = asArray(organization.security_signals);
  const probeCounts = asObject(access.probe_status_counts);
  const depthHtml = Object.entries(depthCounts).map(([depth,count]) => chip(`${depth}: ${count}`, depth)).join(' ') || '<span class="muted">No depth summary</span>';
  const probeHtml = Object.entries(probeCounts).map(([status,count]) => {
    const [label, cls] = statusInfo(status);
    return `<span class="status ${cls}">${escapeHtml(label)}: ${escapeHtml(count)}</span>`;
  }).join(' ');
  const signalHtml = signals.length ? signals.slice(0,8).map(signal => `
    <div class="signal">
      <div class="signal-title">${escapeHtml(signal.title || signal.id)}</div>
      <div class="signal-meta">${escapeHtml(signal.field || signal.source_path || '')}${signal.value !== undefined ? ` = ${escapeHtml(JSON.stringify(signal.value))}` : ''}</div>
    </div>`).join('') : '<div class="empty-state">No potentially insecure organization settings were detected.</div>';

  document.getElementById('tab-overview').innerHTML = overviewCards() + `
    <div class="grid-2">
      <div class="section">
        <div class="section-header"><h2>Target</h2></div>
        <div class="section-body"><div class="kv">
          <div class="key">Display URL</div><div><a href="${escapeHtml(target.display_url || '#')}" target="_blank" rel="noopener">${escapeHtml(target.display_url || '—')}</a></div>
          <div class="key">API base</div><div><a href="${escapeHtml(target.api_base_url || '#')}" target="_blank" rel="noopener">${escapeHtml(target.api_base_url || '—')}</a></div>
          <div class="key">Server version</div><div>${escapeHtml(target.server_version || '—')}</div>
          <div class="key">Organization ID</div><div>${escapeHtml(path(DATA,'identity','OrganizationId') || '—')}</div>
          <div class="key">Business Unit ID</div><div>${escapeHtml(path(DATA,'identity','BusinessUnitId') || '—')}</div>
        </div></div>
      </div>
      <div class="section">
        <div class="section-header"><h2>Privilege depths</h2></div>
        <div class="section-body"><div class="chips">${depthHtml}</div></div>
        <div class="section-header"><h2>Entity probe results</h2></div>
        <div class="section-body"><div class="chips">${probeHtml}</div></div>
      </div>
    </div>
    <div class="section">
      <div class="section-header"><h2>Potential insecure settings</h2><span class="toolbar-count">${signals.length}</span></div>
      <div class="section-body">${signalHtml}</div>
    </div>`;
}

function flattenSettings(settings) {
  const rows = [];
  Object.entries(asObject(settings)).forEach(([group, values]) => {
    Object.entries(asObject(values)).forEach(([key,value]) => rows.push({group,key,value}));
  });
  return rows;
}

function organizationCollectionUrl(selectField='') {
  const apiBase = String(path(DATA,'target','api_base_url') || '').replace(/\/$/, '');
  if (!apiBase) return '';
  const base = `${apiBase}/organizations`;
  return selectField ? `${base}?$select=${encodeURIComponent(selectField)}` : base;
}

function signalSettingUrl(signal) {
  if (signal.source === 'orgdborgsettings') return organizationCollectionUrl('orgdborgsettings');
  return signal.field ? organizationCollectionUrl(signal.field) : organizationCollectionUrl();
}

function renderOrganization() {
  const organization = asObject(DATA.organization);
  const signals = asArray(organization.security_signals);
  const notEvaluated = asArray(organization.checks_not_evaluated);
  const rows = flattenSettings(organization.settings);
  const orgdb = asObject(organization.orgdborgsettings);
  const organizationsUrl = organizationCollectionUrl();
  const settingsRows = rows.map(row => `<tr><td>${escapeHtml(row.group)}</td><td class="entity-name">${escapeHtml(row.key)}</td><td><code>${escapeHtml(typeof row.value === 'string' ? row.value : JSON.stringify(row.value))}</code></td></tr>`).join('');
  const signalRows = signals.map(signal => {
    const settingUrl = signalSettingUrl(signal);
    return `<tr>
      <td>${escapeHtml(signal.category || '')}</td>
      <td class="entity-name">${escapeHtml(signal.title || signal.id || '')}</td>
      <td>${escapeHtml(signal.field || signal.source_path || '')}</td>
      <td><code>${escapeHtml(JSON.stringify(signal.value))}</code></td>
      <td>${escapeHtml(signal.source || '')}</td>
      <td>${settingUrl ? `<a class="open-link" href="${escapeHtml(settingUrl)}" target="_blank" rel="noopener">Check API</a>` : '—'}</td>
    </tr>`;
  }).join('');
  const missingRows = notEvaluated.map(item => `<tr><td class="entity-name">${escapeHtml(item.check || '')}</td><td>${escapeHtml(asArray(item.expected_settings).join(', '))}</td><td>${escapeHtml(item.reason || '')}</td></tr>`).join('');

  document.getElementById('tab-organization').innerHTML = `
    <div class="cards">
      <div class="card"><div class="label">Readable fields</div><div class="value">${escapeHtml(organization.readable_field_count ?? 0)}</div></div>
      <div class="card"><div class="label">Relevant fields</div><div class="value">${escapeHtml(organization.relevant_field_count ?? 0)}</div></div>
      <div class="card"><div class="label">Potential insecure settings</div><div class="value">${escapeHtml(signals.length)}</div></div>
      <div class="card"><div class="label">Checks not evaluated</div><div class="value">${escapeHtml(notEvaluated.length)}</div></div>
      <div class="card"><div class="label">OrgDb settings</div><div class="value">${escapeHtml(orgdb.setting_count ?? 0)}</div></div>
    </div>
    <div class="section"><div class="section-header"><h2>Potential insecure settings</h2><span class="toolbar-count">${signals.length}</span></div><div class="table-wrap"><table><thead><tr><th>Category</th><th>Detected setting</th><th>Field</th><th>Value</th><th>Source</th><th>URL</th></tr></thead><tbody>${signalRows || '<tr><td colspan="6" class="empty-state">No potentially insecure settings detected</td></tr>'}</tbody></table></div></div>
    <div class="section">
      <div class="section-header"><h2>Checks not evaluated</h2><span class="toolbar-count">${notEvaluated.length}</span></div>
      <div class="section-body small muted">These checks were expected by the tool, but no matching readable column was found in <code>organizations</code> and no matching element was found in the parsed <code>OrgDbOrgSettings</code> blob. This is an enumeration gap, not confirmation that the setting is safe.</div>
      <div class="table-wrap"><table><thead><tr><th>Check</th><th>Expected settings</th><th>Reason</th></tr></thead><tbody>${missingRows || '<tr><td colspan="3" class="empty-state">All expected checks were evaluated</td></tr>'}</tbody></table></div>
    </div>
    <div class="section"><div class="section-header"><h2>Readable organization settings</h2><div><span class="toolbar-count">${rows.length}</span>${organizationsUrl ? ` &nbsp; <a class="open-link" href="${escapeHtml(organizationsUrl)}" target="_blank" rel="noopener">Open organizations API</a>` : ''}</div></div><div class="table-wrap"><table><thead><tr><th>Group</th><th>Setting</th><th>Value</th></tr></thead><tbody>${settingsRows || '<tr><td colspan="3" class="empty-state">No settings</td></tr>'}</tbody></table></div></div>
    <div class="section"><div class="section-header"><h2>OrgDbOrgSettings</h2></div><div class="section-body"><details><summary>Parsed OrgDbOrgSettings JSON</summary><pre>${escapeHtml(j(orgdb))}</pre></details></div></div>`;
}

function privilegeRowsFiltered() {
  const inventory = asObject(path(DATA,'security','privilege_inventory'));
  const held = asArray(inventory.held_privileges);
  const search = document.getElementById('privSearch')?.value.toLowerCase().trim() || '';
  const depth = document.getElementById('privDepth')?.value || '';
  const source = document.getElementById('privSource')?.value.toLowerCase().trim() || '';
  return held.filter(item => {
    const labels = sourceLabels(item.sources).join(' ');
    return (!search || String(item.name || item.privilege_id).toLowerCase().includes(search)) &&
      (!depth || item.depth === depth) &&
      (!source || labels.toLowerCase().includes(source));
  });
}

function updatePrivilegeTable() {
  const tbody = document.getElementById('privRows');
  if (!tbody) return;
  const items = privilegeRowsFiltered();
  document.getElementById('privCount').textContent = `${items.length} shown`;
  tbody.innerHTML = items.map(item => {
    const labels = sourceLabels(item.sources);
    return `<tr>
      <td class="priv-name">${escapeHtml(item.name || item.privilege_id)}</td>
      <td>${chip(item.depth || 'None', item.depth)}</td>
      <td>${labels.map(label => chip(label)).join(' ') || '<span class="muted">Source unresolved</span>'}</td>
      <td>${escapeHtml(item.status || '')}</td>
      <td><details><summary>JSON</summary><pre>${escapeHtml(j(item))}</pre></details></td>
    </tr>`;
  }).join('') || '<tr><td colspan="5" class="empty-state">No privileges match the filters.</td></tr>';
}

function renderPrivileges() {
  const security = asObject(DATA.security);
  const inventory = asObject(security.privilege_inventory);
  const summary = asObject(inventory.summary);
  const roleOnly = asArray(inventory.role_derived_not_reported);
  const userOnly = asArray(inventory.user_reported_only);
  document.getElementById('tab-privileges').innerHTML = `
    <div class="cards">
      <div class="card"><div class="label">Held privileges</div><div class="value">${escapeHtml(summary.held_count ?? 0)}</div></div>
      <div class="card"><div class="label">Source attributed</div><div class="value">${escapeHtml(summary.source_attributed_count ?? 0)}</div></div>
      <div class="card"><div class="label">User API only</div><div class="value">${escapeHtml(summary.user_reported_only_count ?? userOnly.length)}</div></div>
      <div class="card"><div class="label">Role-only discrepancy</div><div class="value">${escapeHtml(summary.role_derived_not_reported_count ?? roleOnly.length)}</div></div>
    </div>
    <div class="section">
      <div class="section-header"><h2>Held privilege inventory</h2><span id="privCount" class="toolbar-count"></span></div>
      <div class="filters">
        <input id="privSearch" type="search" placeholder="Search privilege name…">
        <select id="privDepth"><option value="">All depths</option><option>Global</option><option>Deep</option><option>Local</option><option>Basic</option><option>None</option></select>
        <input id="privSource" type="search" placeholder="Filter role/team source…">
      </div>
      <div class="table-wrap"><table><thead><tr><th>Privilege</th><th>Depth</th><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody id="privRows"></tbody></table></div>
    </div>
    <div class="grid-2">
      <div class="section"><div class="section-header"><h2>Role-derived, not user-reported</h2><span class="toolbar-count">${roleOnly.length}</span></div><div class="section-body"><pre>${escapeHtml(j(roleOnly))}</pre></div></div>
      <div class="section"><div class="section-header"><h2>User-reported, source unresolved</h2><span class="toolbar-count">${userOnly.length}</span></div><div class="section-body"><pre>${escapeHtml(j(userOnly))}</pre></div></div>
    </div>`;
  ['privSearch','privDepth','privSource'].forEach(id => document.getElementById(id).addEventListener('input', updatePrivilegeTable));
  updatePrivilegeTable();
}

function entityFilter(scope) {
  const access = asObject(DATA.entity_access || DATA.custom_entities);
  const entities = asArray(access.entities).filter(item => item.scope === scope);
  const prefix = scope === 'custom' ? 'custom' : 'standard';
  const search = document.getElementById(`${prefix}Search`)?.value.toLowerCase().trim() || '';
  const status = document.getElementById(`${prefix}Status`)?.value || '';
  const operation = document.getElementById(`${prefix}Privilege`)?.value || '';
  const depth = document.getElementById(`${prefix}Depth`)?.value || '';
  return entities.filter(entity => {
    const probe = path(entity,'probe','status') || '';
    const privilege = operation ? asObject(path(entity,'privileges',operation)) : null;
    const nameText = `${entity.logical_name || ''} ${entity.schema_name || ''} ${entity.entity_set_name || ''}`.toLowerCase();
    return (!search || nameText.includes(search)) &&
      (!status || probe === status) &&
      (!operation || privilege?.held === true) &&
      (!depth || privilege?.depth === depth);
  });
}

function updateEntityTable(scope) {
  const prefix = scope === 'custom' ? 'custom' : 'standard';
  const tbody = document.getElementById(`${prefix}Rows`);
  if (!tbody) return;
  const items = entityFilter(scope);
  document.getElementById(`${prefix}Count`).textContent = `${items.length} shown`;
  tbody.innerHTML = items.map(entity => {
    const status = path(entity,'probe','status');
    const [label, cls] = statusInfo(status);
    const meta = [entity.ownership_type, entity.is_audit_enabled === true ? 'Audit enabled' : entity.is_audit_enabled === false ? 'Audit disabled' : null].filter(Boolean).join(' · ');
    const visibleCount = path(entity,'probe','visible_record_count');
    return `<tr>
      <td><div class="entity-name">${escapeHtml(entity.logical_name || 'Unknown')}</div></td>
      <td><span class="status ${cls}">${escapeHtml(label)}</span></td>
      <td><div class="chips">${heldPrivilegeChips(entity) || '<span class="muted">No held table privilege mapped</span>'}</div></td>
      <td>${escapeHtml(meta || '—')}</td>
      <td>${visibleCount === undefined || visibleCount === null ? '<span class="muted">Not counted</span>' : escapeHtml(visibleCount)}</td>
      <td>${entity.endpoint_url ? `<a class="open-link" href="${escapeHtml(entity.endpoint_url)}" target="_blank" rel="noopener">Open API</a>` : '—'}</td>
      <td><details><summary>Details</summary><pre>${escapeHtml(j(entity))}</pre></details></td>
    </tr>`;
  }).join('') || '<tr><td colspan="7" class="empty-state">No entities match the filters.</td></tr>';
}

function renderEntityTab(scope) {
  const prefix = scope === 'custom' ? 'custom' : 'standard';
  const title = scope === 'custom' ? 'Custom entities' : 'Default entities';
  const access = asObject(DATA.entity_access || DATA.custom_entities);
  const entities = asArray(access.entities).filter(entity => entity.scope === scope);
  const counts = {};
  entities.forEach(entity => { const status = path(entity,'probe','status') || 'UNKNOWN'; counts[status] = (counts[status] || 0) + 1; });
  document.getElementById(`tab-${prefix}`).innerHTML = `
    <div class="cards">
      <div class="card"><div class="label">Entities</div><div class="value">${entities.length}</div></div>
      <div class="card"><div class="label">Access with data</div><div class="value">${counts.READABLE_WITH_DATA || 0}</div></div>
      <div class="card"><div class="label">No visible data</div><div class="value">${counts.READABLE_EMPTY_OR_FILTERED || 0}</div></div>
      <div class="card"><div class="label">Access denied</div><div class="value">${counts.ACCESS_DENIED || 0}</div></div>
    </div>
    <div class="section">
      <div class="section-header"><h2>${title}</h2><span id="${prefix}Count" class="toolbar-count"></span></div>
      <div class="filters">
        <input id="${prefix}Search" type="search" placeholder="Search entity…">
        <select id="${prefix}Status">
          <option value="">All access states</option>
          <option value="READABLE_WITH_DATA">Access with data</option>
          <option value="READABLE_EMPTY_OR_FILTERED">Access, no visible data</option>
          <option value="ACCESS_DENIED">Access denied</option>
          <option value="INVALID_OR_UNSUPPORTED">Invalid/unsupported</option>
          <option value="BACKEND_ERROR">Backend error</option>
        </select>
        <select id="${prefix}Privilege"><option value="">Any privilege</option>${['Create','Read','Write','Delete','Assign','Share','Append','AppendTo'].map(name => `<option>${name}</option>`).join('')}</select>
        <select id="${prefix}Depth"><option value="">Any depth</option><option>Global</option><option>Deep</option><option>Local</option><option>Basic</option></select>
      </div>
      <div class="table-wrap"><table><thead><tr><th>Entity</th><th>Access</th><th>Held privileges</th><th>Metadata</th><th>Visible records</th><th>URL</th><th>Details</th></tr></thead><tbody id="${prefix}Rows"></tbody></table></div>
    </div>`;
  [`${prefix}Search`,`${prefix}Status`,`${prefix}Privilege`,`${prefix}Depth`].forEach(id => document.getElementById(id).addEventListener('input', () => updateEntityTable(scope)));
  updateEntityTable(scope);
}

function secretFindingsFiltered() {
  const scan = asObject(DATA.secret_scan);
  const findings = asArray(scan.findings);
  const search = document.getElementById('secretSearch')?.value.toLowerCase().trim() || '';
  const category = document.getElementById('secretCategory')?.value || '';
  const scope = document.getElementById('secretScope')?.value || '';
  const method = document.getElementById('secretMethod')?.value || '';
  return findings.filter(item => {
    const haystack = [
      item.category_label, item.category, item.entity_logical_name, item.entity_set_name,
      item.key_field, item.key_value, item.value_field, item.source_path,
      item.masked_value, item.detection_method,
    ].join(' ').toLowerCase();
    return (!search || haystack.includes(search)) &&
      (!category || item.category === category) &&
      (!scope || item.scope === scope) &&
      (!method || item.detection_method === method);
  });
}

function updateSecretTable() {
  const tbody = document.getElementById('secretRows');
  if (!tbody) return;
  const items = secretFindingsFiltered();
  document.getElementById('secretCount').textContent = `${items.length} shown`;
  tbody.innerHTML = items.map(item => {
    const recordLabel = item.key_value || item.record_id || '—';
    const fieldLabel = item.key_field && item.key_value
      ? `${item.key_field} → ${item.value_field || item.source_path || ''}`
      : (item.source_path || item.value_field || '—');
    return `<tr>
      <td><span class="status denied">${escapeHtml(item.category_label || item.category || 'Flagged value')}</span></td>
      <td class="entity-name">${escapeHtml(item.entity_logical_name || 'Unknown')}</td>
      <td><code>${escapeHtml(recordLabel)}</code></td>
      <td><code>${escapeHtml(fieldLabel)}</code><div class="small muted">${escapeHtml(item.detection_method || '')}</div></td>
      <td><code>${escapeHtml(item.masked_value || '—')}</code><div class="small muted">Length ${escapeHtml(item.value_length ?? '—')} · SHA-256 ${escapeHtml(String(item.sha256 || '').slice(0,12))}…</div></td>
      <td>${item.verification_url ? `<a class="open-link" href="${escapeHtml(item.verification_url)}" target="_blank" rel="noopener">Verify in API</a>` : '—'}</td>
      <td><details><summary>Details</summary><pre>${escapeHtml(j(item))}</pre></details></td>
    </tr>`;
  }).join('') || '<tr><td colspan="7" class="empty-state">No flagged values match the filters.</td></tr>';
}

function renderSecrets() {
  const scan = asObject(DATA.secret_scan);
  const findings = asArray(scan.findings);
  const entities = asArray(scan.entities);
  const errors = asArray(scan.errors);
  const categories = [...new Set(findings.map(item => item.category).filter(Boolean))].sort();
  const methods = [...new Set(findings.map(item => item.detection_method).filter(Boolean))].sort();
  const entityRows = entities.map(item => `<tr>
    <td class="entity-name">${escapeHtml(item.entity_logical_name || '')}</td>
    <td>${item.config_store ? '<span class="status empty">Configuration store</span>' : '<span class="status other">Targeted fields</span>'}</td>
    <td>${escapeHtml(item.attribute_count ?? 0)}</td>
    <td>${escapeHtml(item.records_inspected ?? 0)}</td>
    <td>${escapeHtml(item.finding_count ?? 0)}</td>
    <td>${item.query_url ? `<a class="open-link" href="${escapeHtml(item.query_url)}" target="_blank" rel="noopener">Open scan query</a>` : '—'}</td>
    <td><details><summary>Candidate fields</summary><pre>${escapeHtml(j(item.candidate_attributes || []))}</pre></details></td>
  </tr>`).join('');

  document.getElementById('tab-secrets').innerHTML = `
    <div class="cards">
      <div class="card"><div class="label">Flagged values</div><div class="value">${escapeHtml(scan.finding_count ?? findings.length)}</div></div>
      <div class="card"><div class="label">Candidate entities</div><div class="value">${escapeHtml(scan.candidate_entity_count ?? entities.length)}</div></div>
      <div class="card"><div class="label">Records inspected</div><div class="value">${escapeHtml(scan.records_inspected ?? 0)}</div></div>
      <div class="card"><div class="label">Readable entities considered</div><div class="value">${escapeHtml(scan.readable_entities_considered ?? 0)}</div></div>
      <div class="card"><div class="label">Scan errors</div><div class="value">${escapeHtml(errors.length)}</div></div>
    </div>
    <div class="section">
      <div class="section-header"><h2>Potential secret and configuration exposures</h2><span id="secretCount" class="toolbar-count"></span></div>
      <div class="section-body small muted">Values are masked in the JSON and dashboard. Use the record-specific verification link to retrieve the selected fields directly from Dynamics 365.</div>
      <div class="filters">
        <input id="secretSearch" type="search" placeholder="Search entity, setting key, field…">
        <select id="secretCategory"><option value="">All categories</option>${categories.map(value => `<option value="${escapeHtml(value)}">${escapeHtml((findings.find(item => item.category === value) || {}).category_label || value)}</option>`).join('')}</select>
        <select id="secretScope"><option value="">Default and custom</option><option value="sensitive_standard">Default entities</option><option value="custom">Custom entities</option></select>
        <select id="secretMethod"><option value="">All detection methods</option>${methods.map(value => `<option value="${escapeHtml(value)}">${escapeHtml(value.replaceAll('_',' '))}</option>`).join('')}</select>
      </div>
      <div class="table-wrap"><table><thead><tr><th>Type</th><th>Entity</th><th>Record key / ID</th><th>Field</th><th>Masked value</th><th>URL</th><th>Details</th></tr></thead><tbody id="secretRows"></tbody></table></div>
    </div>
    <div class="section">
      <div class="section-header"><h2>Scanned candidate entities</h2><span class="toolbar-count">${entities.length}</span></div>
      <div class="table-wrap"><table><thead><tr><th>Entity</th><th>Mode</th><th>Attributes</th><th>Records</th><th>Flags</th><th>Query</th><th>Fields</th></tr></thead><tbody>${entityRows || '<tr><td colspan="7" class="empty-state">No candidate entities were scanned.</td></tr>'}</tbody></table></div>
    </div>
    ${errors.length ? `<div class="section"><div class="section-header"><h2>Scan errors</h2><span class="toolbar-count">${errors.length}</span></div><div class="section-body"><pre>${escapeHtml(j(errors))}</pre></div></div>` : ''}`;
  ['secretSearch','secretCategory','secretScope','secretMethod'].forEach(id => document.getElementById(id).addEventListener('input', updateSecretTable));
  updateSecretTable();
}

function collectErrors(root, prefix='root', found=[]) {
  if (Array.isArray(root)) {
    root.forEach((value,index) => collectErrors(value, `${prefix}[${index}]`, found));
    return found;
  }
  if (!root || typeof root !== 'object') return found;
  const status = root.status;
  if (status && ['error','unexpected_response','not_found'].includes(String(status).toLowerCase())) {
    found.push({path:prefix,status,error:root.error,http_status:root.http_status});
  }
  Object.entries(root).forEach(([key,value]) => {
    if (!['raw_response','flat_settings'].includes(key)) collectErrors(value, `${prefix}.${key}`, found);
  });
  return found;
}

function renderErrors() {
  const errors = collectErrors(DATA);
  const errorRows = errors.map(item => `<tr><td><code>${escapeHtml(item.path)}</code></td><td>${escapeHtml(item.status || '')}</td><td>${escapeHtml(item.http_status ?? '')}</td><td>${escapeHtml(item.error || '')}</td></tr>`).join('');
  document.getElementById('tab-errors').innerHTML = `
    <div class="section"><div class="section-header"><h2>Recorded errors</h2><span class="toolbar-count">${errors.length}</span></div><div class="table-wrap"><table><thead><tr><th>Path</th><th>Status</th><th>HTTP</th><th>Error</th></tr></thead><tbody>${errorRows || '<tr><td colspan="4" class="empty-state">No recorded errors found.</td></tr>'}</tbody></table></div></div>
    <div class="section"><div class="section-header"><h2>Raw enumeration JSON</h2></div><div class="section-body"><div class="raw-actions"><button id="copyRaw" class="action-button">Copy JSON</button><a class="action-button" href="/api/results" target="_blank">Open JSON endpoint</a></div><pre id="rawJson">${escapeHtml(j(DATA))}</pre></div></div>`;
  document.getElementById('copyRaw').addEventListener('click', async event => {
    await navigator.clipboard.writeText(j(DATA));
    event.target.textContent = 'Copied';
    setTimeout(() => event.target.textContent = 'Copy JSON', 1200);
  });
}

function renderAll() {
  const target = asObject(DATA.target);
  document.getElementById('subtitle').textContent = `${target.organization_name || path(DATA,'organization','name') || 'Unknown organization'} · ${target.display_url || 'Unknown target'} · ${target.api_version || ''}`;
  renderOverview();
  renderOrganization();
  renderPrivileges();
  renderSecrets();
  renderEntityTab('sensitive_standard');
  renderEntityTab('custom');
  renderErrors();
}

async function loadData() {
  try {
    const response = await fetch('/api/results', {cache: 'no-store'});
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    DATA = await response.json();
    renderAll();
  } catch (error) {
    const box = document.getElementById('loadError');
    box.style.display = 'block';
    box.textContent = `Could not load enumeration JSON:\n${error}`;
    document.getElementById('subtitle').textContent = 'Failed to load data';
  }
}
loadData();
</script>
</body>
</html>'''


class DashboardServer(ThreadingHTTPServer):
    """HTTP server carrying the selected JSON path."""

    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], json_path: Path):
        self.json_path = json_path
        super().__init__(server_address, DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Keep the dashboard quiet; startup information is printed explicitly.
        return

    def _send_bytes(self, payload: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if route == "/":
            self._send_bytes(DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if route == "/api/results":
            try:
                raw = self.server.json_path.read_text(encoding="utf-8")
                data = json.loads(raw)
                payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
            except FileNotFoundError:
                payload = json.dumps({"error": f"File not found: {self.server.json_path}"}).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8", HTTPStatus.NOT_FOUND)
            except json.JSONDecodeError as exc:
                payload = json.dumps({"error": f"Invalid JSON: {exc}"}).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8", HTTPStatus.BAD_REQUEST)
            except OSError as exc:
                payload = json.dumps({"error": str(exc)}).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8", HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if route == "/favicon.ico":
            self._send_bytes(b"", "image/x-icon", HTTPStatus.NO_CONTENT)
            return
        self._send_bytes(b"Not found", "text/plain; charset=utf-8", HTTPStatus.NOT_FOUND)


def serve_dashboard(
    json_path: Path | str,
    *,
    port: int = 8765,
    open_browser: bool = True,
) -> None:
    """Run the dashboard until interrupted."""
    path = Path(json_path).expanduser().resolve()
    server = DashboardServer(("127.0.0.1", port), path)
    url = f"http://127.0.0.1:{port}/"
    print("\nD365 dashboard")
    print("--------------")
    print(f"JSON : {path}")
    print(f"URL  : {url}")
    print("Press Ctrl+C to stop.")

    if open_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Open a local dashboard for d365_enum.json")
    parser.add_argument("--input", type=Path, default=Path("d365_enum.json"), help="Enumeration JSON file")
    parser.add_argument("--port", type=int, default=8765, help="Local TCP port (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the browser")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    serve_dashboard(args.input, port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
