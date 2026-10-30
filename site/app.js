import appConfig from './config.js';
import { generateKeyPair } from './lib/x25519.js';
import { createZip } from './lib/zip.js';
import { buildUci, isValidIfaceName, DEFAULT_OPENWRT } from './lib/openwrt.js';
import {
  DEFAULT_SETTINGS, ENDPOINT_HOSTS, parseConfigText, ENDPOINT_PORTS, DNS_GROUPS, DNS_PRESETS, presetForDns, configFileName, hostNumber, portLetter, batchConfigs, batchArchiveName, deviceHosts, MAX_DEVICES,
  parseRegistration, buildConfig, validateSettings,
} from './lib/warp.js';

const $ = (id) => document.getElementById(id);
const STORE_KEY = 'warpgen.settings.v1';
const CUSTOM = '__custom__';
const AWG_FIELDS = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'];

let registration = null; // selected device's registration; kept in memory only, never stored
let registrations = []; // one per device, each with its own key (and port when several)
let selected = 0;
let canShareZip = false;
let currentConfig = '';

// ---------- settings ----------
function loadSettings() {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(STORE_KEY) || '{}'); } catch { /* storage unavailable */ }
  const s = { ...DEFAULT_SETTINGS, mode: 'santa', ...saved };
  if (saved.dns && !saved.dnsPreset) s.dnsPreset = presetForDns(saved.dns);
  // On the published site the Worker is fixed by WORKER_URL (and allowed by the
  // page's CSP); the field is only for local runs without a deploy.
  if (appConfig.workerUrl) s.workerUrl = appConfig.workerUrl;
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
    excludeLan: $('excludeLan').checked,
    owIface: $('owIface').value.trim(),
    deviceCount: Number($('deviceCount').value) || 1,
    owRouteAll: $('owRouteAll').checked,
    mtu: Number($('mtu').value),
    keepalive: Number($('keepalive').value),
    ipv6: $('ipv6').checked,
    workerUrl: $('workerUrl').value.trim().replace(/\/+$/, ''),
    batchHosts: batchState.hosts,
    batchPorts: batchState.ports,
  };
  for (const f of AWG_FIELDS) s[f] = Number($(f).value);
  return s;
}

function fillForm(s) {
  (document.querySelector(`input[name="mode"][value="${s.mode}"]`) || document.querySelector('input[name="mode"]')).checked = true;
  updateModeUi();

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
  $('excludeLan').checked = Boolean(s.excludeLan);
  $('owIface').value = s.owIface || DEFAULT_OPENWRT.iface;
  $('deviceCount').value = String(Math.min(Math.max(Number(s.deviceCount) || 1, 1), MAX_DEVICES));
  $('owRouteAll').checked = Boolean(s.owRouteAll);
  $('mtu').value = s.mtu;
  $('keepalive').value = s.keepalive;
  $('ipv6').checked = s.ipv6;
  $('workerUrl').value = s.workerUrl;
}

function buildStaticControls() {
  const sel = $('endpointHost');
  for (const h of ENDPOINT_HOSTS) sel.add(new Option(`${hostNumber(h)}. ${h}`, h));
  sel.add(new Option('0. Свой адрес…', CUSTOM));

  const ports = $('ports');
  for (const p of ENDPOINT_PORTS) {
    const label = document.createElement('label');
    label.innerHTML = `<input type="radio" name="port" value="${p}"><span>${portLetter(p)}. ${p}</span>`;
    ports.append(label);
  }

  const bh = $('batchHosts');
  for (const h of ENDPOINT_HOSTS) {
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" name="batchHost" value="${h}"><span>${hostNumber(h)}. ${h}</span>`;
    bh.append(label);
  }
  const bp = $('batchPorts');
  for (const p of ENDPOINT_PORTS) {
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" name="batchPort" value="${p}"><span>${portLetter(p)}. ${p}</span>`;
    bp.append(label);
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

// ---------- import of an existing config ----------
function updateModeUi() {
  const mode = document.querySelector('input[name="mode"]:checked').value;
  $('importPanel').hidden = mode !== 'import';
  $('deviceCountField').hidden = mode === 'import';
  const n = Number($('deviceCount').value) || 1;
  $('generate').textContent = mode === 'import' ? 'Открыть конфиг' : n > 1 ? `Получить конфиги: ${n}` : 'Получить конфиг';
}

function importConfig() {
  const text = $('importText').value;
  if (!text.trim()) throw new Error('Вставьте текст конфига или выберите файл.');
  const { reg, settings, notes } = parseConfigText(text);
  fillForm({ ...readForm(), ...settings, mode: 'import' });
  saveSettings(readForm());
  return { reg, notes };
}

async function readImportFile() {
  const file = $('importFile').files[0];
  if (!file) return;
  if (file.size > 64 * 1024) {
    setStatus('Файл слишком большой для конфига WireGuard.', 'err');
    return;
  }
  $('importText').value = await file.text();
  $('importFile').value = '';
  generate();
}

// ---------- batch of endpoint variants ----------
let batchState = { hosts: [...ENDPOINT_HOSTS], ports: [] };

function loadBatch(s) {
  const hosts = Array.isArray(s.batchHosts) ? s.batchHosts.filter((h) => ENDPOINT_HOSTS.includes(h)) : [...ENDPOINT_HOSTS];
  const ports = Array.isArray(s.batchPorts) ? s.batchPorts.map(Number).filter((p) => ENDPOINT_PORTS.includes(p)) : [Number(s.endpointPort) || 500];
  batchState = { hosts, ports };
  for (const el of document.querySelectorAll('input[name="batchHost"]')) el.checked = hosts.includes(el.value);
  for (const el of document.querySelectorAll('input[name="batchPort"]')) el.checked = ports.includes(Number(el.value));
}

function readBatch() {
  batchState = {
    hosts: [...document.querySelectorAll('input[name="batchHost"]:checked')].map((el) => el.value),
    ports: [...document.querySelectorAll('input[name="batchPort"]:checked')].map((el) => Number(el.value)),
  };
  return batchState;
}

function updateBatchUi() {
  const { hosts, ports } = readBatch();
  const n = hosts.length * ports.length;
  const files = n === 1 ? 'файл' : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? 'файла' : 'файлов';
  $('batchDownload').textContent = n ? `Скачать набор: ${n} ${files}` : 'Отметьте адрес и порт';
  $('batchDownload').disabled = n === 0;
  $('batchShare').disabled = n === 0;
}

function batchZip() {
  const s = effective();
  const { hosts, ports } = readBatch();
  const files = batchConfigs(registration, s, hosts, ports);
  const name = batchArchiveName(registration, s);
  return new File([createZip(files.map((f) => ({ name: f.name, data: f.text })))], name, { type: 'application/zip' });
}

function downloadBatch() {
  if (validateSettings(readForm()).length) return render();
  const file = batchZip();
  const url = URL.createObjectURL(file);
  const a = document.createElement('a');
  a.href = url;
  a.download = file.name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  setStatus(`Архив ${file.name} скачан.`, 'ok');
}

async function shareBatch() {
  if (validateSettings(readForm()).length) return render();
  try {
    const file = batchZip();
    await navigator.share({ files: [file], title: file.name });
  } catch (e) {
    if (e.name !== 'AbortError') setStatus('Не удалось отправить архив: ' + e.message, 'err');
  }
}

function onBatchChange() {
  readBatch();
  saveSettings(readForm());
  updateBatchUi();
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
    if (res.status === 429) {
      throw new Error('Слишком много запросов с вашего адреса. Подождите минуту и попробуйте снова.');
    }
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
  const s = effective();
  const errs = validateSettings(s);
  if (errs.length) {
    setStatus('Проверьте параметры: ' + errs.join('; '), 'err');
    return;
  }
  currentConfig = buildConfig(registration, s);
  $('config').textContent = currentConfig;

  const src = { local: 'ключ создан в этом браузере', import: 'ключ из вашего конфига', santa: 'ключ создан сервером Santa' }[registration.source];
  const multi = registrations.length > 1;
  const parts = [multi ? `устройство ${selected + 1} из ${registrations.length}, ${src}` : src, `адрес ${registration.v4}`];
  if (registration.license) parts.push(`лицензия ${registration.license}`);
  $('result-meta').textContent = parts.join(', ');
  $('download').textContent = `Скачать ${fileName()}`;
  renderDevices();
  if (!multi) renderUci(s);
}

function renderDevices() {
  const multi = registrations.length > 1;
  $('result-title').textContent = multi ? 'Ваши конфиги' : 'Ваш конфиг';
  $('devices').hidden = !multi;
  $('downloadAll').hidden = !multi;
  $('shareAll').hidden = !multi || !canShareZip;
  $('openwrt').hidden = multi;
  $('ports').closest('fieldset').disabled = multi;
  $('portNote').hidden = !multi;
  if (!multi) return;
  $('downloadAll').textContent = `Скачать все: ${registrations.length}`;
  const base = readForm();
  const hosts = deviceHosts(base.endpointHost, registrations.length);
  const list = $('deviceList');
  list.replaceChildren(...registrations.map((reg, i) => {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'radio';
    input.name = 'device';
    input.value = String(i);
    input.checked = i === selected;
    const span = document.createElement('span');
    span.textContent = configFileName(reg, { ...base, endpointHost: hosts[i], endpointPort: reg.port }).replace(/\.conf$/, '');
    label.append(input, span);
    return label;
  }));
}

function allConfigsZip() {
  const base = readForm();
  const hosts = deviceHosts(base.endpointHost, registrations.length);
  const files = registrations.map((reg, i) => {
    const s = { ...base, endpointHost: hosts[i], endpointPort: reg.port };
    return { name: configFileName(reg, s), data: buildConfig(reg, s) };
  });
  const name = batchArchiveName(registrations[0], base).replace(/\.zip$/, '_devices.zip');
  return new File([createZip(files)], name, { type: 'application/zip' });
}

function downloadAll() {
  if (validateSettings(effective()).length) return render();
  const file = allConfigsZip();
  const url = URL.createObjectURL(file);
  const a = document.createElement('a');
  a.href = url;
  a.download = file.name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  setStatus(`Архив ${file.name} скачан.`, 'ok');
}

async function shareAll() {
  if (validateSettings(effective()).length) return render();
  try {
    const file = allConfigsZip();
    await navigator.share({ files: [file], title: file.name });
  } catch (e) {
    if (e.name !== 'AbortError') setStatus('Не удалось отправить архив: ' + e.message, 'err');
  }
}

function renderUci(s = readForm()) {
  if (!registration) return;
  const ok = isValidIfaceName(s.owIface);
  $('owIface').classList.toggle('bad', !ok);
  $('uciCopy').disabled = !ok;
  $('uci').textContent = ok
    ? buildUci(registration, s, { iface: s.owIface, routeAll: s.owRouteAll })
    : 'Имя интерфейса: латинские строчные буквы, цифры и _, до 11 символов, начинается с буквы. Например, awg10.';
}

async function copyUci() {
  const text = $('uci').textContent;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const range = document.createRange();
    range.selectNodeContents($('uci'));
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    document.execCommand('copy');
    sel.removeAllRanges();
  }
  setStatus('Команды для OpenWrt скопированы.', 'ok');
}


// Settings for the selected device: with several devices each gets the next
// host in a circle and its own random port fixed at registration.
function effective(s = readForm()) {
  if (registrations.length < 2) return s;
  const hosts = deviceHosts(s.endpointHost, registrations.length);
  return { ...s, endpointHost: hosts[selected], endpointPort: registration.port };
}

function fileName() {
  return configFileName(registration, effective());
}

// Download: application/octet-stream, otherwise mobile Chrome and Safari see a
// text file and save it as *.conf.txt. Share: text/plain, because the Web Share
// API on Android only accepts a whitelist of types, and the name is kept there.
function configFile(type = 'application/octet-stream') {
  return new File([currentConfig], fileName(), { type });
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
  a.download = fileName();
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  setStatus(`Файл ${a.download} скачан.`, 'ok');
}

async function shareConfig() {
  try {
    const file = configFile('text/plain');
    await navigator.share({ files: [file], title: file.name });
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
    let done = 'Готово. Конфиг зарегистрирован в Cloudflare WARP.';
    if (s.mode === 'import') {
      const { reg, notes } = importConfig();
      registration = reg;
      done = 'Конфиг открыт. Меняйте параметры ниже, ключ останется прежним.' + (notes.length ? ` Обратите внимание: ${notes.join('; ')}.` : '');
      registrations = [reg];
    } else {
      const n = Math.min(Math.max(s.deviceCount || 1, 1), MAX_DEVICES);
      const got = [];
      let failure = null;
      for (let i = 0; i < n; i++) {
        if (n > 1) setStatus(`Регистрирую устройство ${i + 1} из ${n}…`);
        try {
          got.push(s.mode === 'local' ? await registerLocally(s.workerUrl) : await registerViaSanta(s.workerUrl));
        } catch (e) {
          failure = e;
          break;
        }
      }
      if (!got.length) throw failure;
      if (got.length > 1) {
        const rnd = crypto.getRandomValues(new Uint32Array(got.length));
        got.forEach((reg, i) => { reg.port = ENDPOINT_PORTS[rnd[i] % ENDPOINT_PORTS.length]; });
      }
      registrations = got;
      registration = got[0];
      if (n > 1) done = `Готово. Зарегистрировано устройств: ${got.length}.`;
      if (failure) done = `Получено ${got.length} из ${n}: ${failure.message}`;
    }
    selected = 0;
    $('result').hidden = false;
    render();
    setStatus(done, done.startsWith('Получено') ? 'err' : 'ok');
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
  if (appConfig.workerUrl) $('proxy-details').hidden = true;
  const initial = loadSettings();
  fillForm(initial);
  loadBatch(initial);
  updateBatchUi();

  const canShareFile = (name, type) => {
    try { return !!(navigator.canShare && navigator.canShare({ files: [new File(['x'], name, { type })] })); } catch { return false; }
  };
  $('share').hidden = !canShareFile('x.conf', 'text/plain');
  canShareZip = canShareFile('x.zip', 'application/zip');
  $('batchShare').hidden = !canShareZip;

  $('batch').addEventListener('change', onBatchChange);
  $('deviceCount').addEventListener('change', () => { updateModeUi(); saveSettings(readForm()); });
  $('deviceList').addEventListener('change', (e) => {
    selected = Number(e.target.value) || 0;
    registration = registrations[selected];
    render();
  });
  $('downloadAll').addEventListener('click', downloadAll);
  $('shareAll').addEventListener('click', shareAll);
  const onOpenwrt = () => { saveSettings(readForm()); renderUci(); };
  $('openwrt').addEventListener('input', onOpenwrt);
  $('openwrt').addEventListener('change', onOpenwrt);
  $('uciCopy').addEventListener('click', copyUci);
  $('batchDownload').addEventListener('click', downloadBatch);
  $('batchShare').addEventListener('click', shareBatch);
  $('batchAll').addEventListener('click', () => {
    for (const el of document.querySelectorAll('input[name="batchHost"]')) el.checked = true;
    onBatchChange();
  });
  $('batchNone').addEventListener('click', () => {
    for (const el of document.querySelectorAll('input[name="batchHost"]')) el.checked = false;
    onBatchChange();
  });

  $('generate').addEventListener('click', generate);
  document.querySelector('.mode').addEventListener('change', () => { updateModeUi(); saveSettings(readForm()); });
  $('importFile').addEventListener('change', readImportFile);
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
window.__appReady = true;
