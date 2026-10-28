import appConfig from './config.js';
import { generateKeyPair } from './lib/x25519.js';
import {
  DEFAULT_SETTINGS, ENDPOINT_HOSTS, ENDPOINT_PORTS, DNS_GROUPS, DNS_PRESETS, presetForDns,
  parseRegistration, buildConfig, validateSettings,
} from './lib/warp.js';

const $ = (id) => document.getElementById(id);
const STORE_KEY = 'warpgen.settings.v1';
const CUSTOM = '__custom__';
const AWG_FIELDS = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'];

let registration = null; // kept in memory only, never stored
let currentConfig = '';

// ---------- settings ----------
function loadSettings() {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(STORE_KEY) || '{}'); } catch { /* storage unavailable */ }
  const s = { ...DEFAULT_SETTINGS, mode: 'santa', ...saved };
  if (saved.dns && !saved.dnsPreset) s.dnsPreset = presetForDns(saved.dns);
  if (!s.workerUrl) s.workerUrl = appConfig.workerUrl || '';
  return s;
}

function saveSettings(s) {
  try { localStorage.setItem(STORE_KEY, JSON.stringify(s)); } catch { /* ignore */ }
}

function readForm() {
  const hostSel = $('endpointHost').value;
  const s = {
    mode: document.querySelector('input[name="mode"]:checked').value,
    endpointHost: hostSel === CUSTOM ? $('customHost').value.trim() : hostSel,
    customHost: $('customHost').value.trim(),
    endpointPort: Number(document.querySelector('input[name="port"]:checked')?.value || 500),
    useI1: $('useI1').checked,
    I1: $('I1').value,
    dnsPreset: $('dnsPreset').value,
    dns: $('dns').value.trim(),
    allowedIPs: $('allowedIPs').value.trim(),
    mtu: Number($('mtu').value),
    keepalive: Number($('keepalive').value),
    ipv6: $('ipv6').checked,
    workerUrl: $('workerUrl').value.trim().replace(/\/+$/, ''),
  };
  for (const f of AWG_FIELDS) s[f] = Number($(f).value);
  return s;
}

function fillForm(s) {
  document.querySelector(`input[name="mode"][value="${s.mode}"]`).checked = true;

  const known = ENDPOINT_HOSTS.includes(s.endpointHost);
  $('endpointHost').value = known ? s.endpointHost : CUSTOM;
  $('customHost').value = known ? (s.customHost || '') : s.endpointHost;
  $('customHostField').hidden = known;

  const port = document.querySelector(`input[name="port"][value="${s.endpointPort}"]`)
    || document.querySelector('input[name="port"][value="500"]');
  port.checked = true;

  for (const f of AWG_FIELDS) $(f).value = s[f];
  $('useI1').checked = s.useI1;
  $('I1').value = s.I1;
  $('i1Field').hidden = !s.useI1;
  $('dnsPreset').value = s.dnsPreset;
  $('dns').value = s.dns;
  updateDnsUi();
  $('allowedIPs').value = s.allowedIPs;
  $('mtu').value = s.mtu;
  $('keepalive').value = s.keepalive;
  $('ipv6').checked = s.ipv6;
  $('workerUrl').value = s.workerUrl;
}

function buildStaticControls() {
  const sel = $('endpointHost');
  for (const h of ENDPOINT_HOSTS) sel.add(new Option(h, h));
  sel.add(new Option('Свой адрес…', CUSTOM));

  const ports = $('ports');
  for (const p of ENDPOINT_PORTS) {
    const label = document.createElement('label');
    label.innerHTML = `<input type="radio" name="port" value="${p}"><span>${p}</span>`;
    ports.append(label);
  }

  const dnsSel = $('dnsPreset');
  for (const g of DNS_GROUPS) {
    const og = document.createElement('optgroup');
    og.label = g.name;
    for (const p of DNS_PRESETS.filter((x) => x.group === g.id)) og.append(new Option(p.name, p.id));
    dnsSel.append(og);
  }
  const own = document.createElement('optgroup');
  own.label = 'Другое';
  own.append(new Option('Свои серверы…', 'custom'));
  dnsSel.append(own);

  const grid = $('awg-grid');
  for (const f of AWG_FIELDS) {
    const div = document.createElement('div');
    div.className = 'field';
    div.innerHTML = `<label for="${f}">${f}</label><input id="${f}" type="number" inputmode="numeric" min="0">`;
    grid.append(div);
  }
}

function updateDnsUi() {
  const id = $('dnsPreset').value;
  const preset = DNS_PRESETS.find((p) => p.id === id);
  $('customDnsField').hidden = Boolean(preset);
  $('dnsNote').textContent = preset
    ? `${preset.note} ${preset.servers.filter((x) => !x.includes(':')).join(', ')}`
    : 'Обычные IP-адреса через запятую. DoH и DoT в конфиге WireGuard не поддерживаются.';
}

// ---------- status ----------
function setStatus(text, kind = '') {
  const el = $('status');
  el.textContent = text;
  el.className = 'status' + (kind ? ' ' + kind : '');
}

// ---------- network ----------
async function fetchJson(url, init = {}, timeoutMs = 30000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal, cache: 'no-store' });
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { throw new Error(`сервер ответил не JSON (HTTP ${res.status})`); }
    if (!res.ok) {
      const msg = json?.errors?.[0]?.message || json?.error || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return json;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('сервер не ответил за 30 секунд');
    throw e;
  } finally {
    clearTimeout(t);
  }
}

async function registerViaSanta(workerUrl) {
  if (!workerUrl) {
    throw new Error('Не задан адрес прокси. Укажите адрес Worker в разделе «Прокси».');
  }
  setStatus('Запрашиваю конфиг у Santa…');
  return parseRegistration(await fetchJson(`${workerUrl}/santa`));
}

async function registerLocally(workerUrl) {
  if (!workerUrl) {
    throw new Error('Для этого режима нужен свой прокси. Укажите адрес Worker в разделе «Прокси».');
  }
  setStatus('Создаю ключ в браузере…');
  const { privateKey, publicKey } = generateKeyPair();
  setStatus('Регистрирую публичный ключ в Cloudflare…');
  const json = await fetchJson(`${workerUrl}/reg`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key: publicKey }),
  });
  return parseRegistration(json, privateKey);
}

// ---------- output ----------
function render() {
  if (!registration) return;
  const s = readForm();
  const errs = validateSettings(s);
  if (errs.length) {
    setStatus('Проверьте параметры: ' + errs.join('; '), 'err');
    return;
  }
  currentConfig = buildConfig(registration, s);
  $('config').textContent = currentConfig;

  const src = registration.source === 'local' ? 'ключ создан в этом браузере' : 'ключ создан сервером Santa';
  const parts = [src, `адрес ${registration.v4}`];
  if (registration.license) parts.push(`лицензия ${registration.license}`);
  $('result-meta').textContent = parts.join(', ');
}


function configFile() {
  return new File([currentConfig], 'warp.conf', { type: 'text/plain' });
}

async function copyConfig() {
  try {
    await navigator.clipboard.writeText(currentConfig);
  } catch {
    const range = document.createRange();
    range.selectNodeContents($('config'));
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    document.execCommand('copy');
    sel.removeAllRanges();
  }
  setStatus('Конфиг скопирован.', 'ok');
}

function downloadConfig() {
  const url = URL.createObjectURL(configFile());
  const a = document.createElement('a');
  a.href = url;
  a.download = 'warp.conf';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  setStatus('Файл warp.conf скачан.', 'ok');
}

async function shareConfig() {
  try {
    await navigator.share({ files: [configFile()], title: 'warp.conf' });
  } catch (e) {
    if (e.name !== 'AbortError') setStatus('Не удалось отправить файл: ' + e.message, 'err');
  }
}

// ---------- main ----------
async function generate() {
  const s = readForm();
  saveSettings(s);
  const btn = $('generate');
  btn.disabled = true;
  try {
    registration = s.mode === 'local' ? await registerLocally(s.workerUrl) : await registerViaSanta(s.workerUrl);
    $('result').hidden = false;
    render();
    setStatus('Готово. Конфиг зарегистрирован в Cloudflare WARP.', 'ok');
    $('result').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  } catch (e) {
    setStatus(e.message || String(e), 'err');
    if (/Worker|прокси/.test(e.message || '')) $('proxy-details').open = true;
  } finally {
    btn.disabled = false;
  }
}

function init() {
  buildStaticControls();
  fillForm(loadSettings());

  const canShare = !!(navigator.canShare && navigator.canShare({ files: [new File(['x'], 'x.conf', { type: 'text/plain' })] }));
  $('share').hidden = !canShare;

  $('generate').addEventListener('click', generate);
  $('copy').addEventListener('click', copyConfig);
  $('download').addEventListener('click', downloadConfig);
  $('share').addEventListener('click', shareConfig);

  $('endpointHost').addEventListener('change', () => {
    const custom = $('endpointHost').value === CUSTOM;
    $('customHostField').hidden = !custom;
    if (custom) $('customHost').focus();
  });
  $('useI1').addEventListener('change', () => { $('i1Field').hidden = !$('useI1').checked; });
  $('dnsPreset').addEventListener('change', () => {
    updateDnsUi();
    if ($('dnsPreset').value === 'custom') $('dns').focus();
  });
  $('reset').addEventListener('click', () => {
    fillForm({ ...readForm(), ...pick(DEFAULT_SETTINGS, [...AWG_FIELDS, 'useI1', 'I1']) });
    onChange();
  });

  const onChange = () => {
    saveSettings(readForm());
    if (registration) {
      render();
      if (!validateSettings(readForm()).length) setStatus('Конфиг пересобран.', 'ok');
    }
  };
  document.querySelector('.settings').addEventListener('input', onChange);
  document.querySelector('.settings').addEventListener('change', onChange);
}

function pick(obj, keys) {
  return Object.fromEntries(keys.map((k) => [k, obj[k]]));
}

init();
