// OpenWrt export: shell commands that create an AmneziaWG interface via uci.
// Option names follow the amneziawg proto from github.com/Slava-Shchipunov/awg-openwrt
// (packages kmod-amneziawg, amneziawg-tools, luci-proto-amneziawg).
import { buildConfig } from './warp.js';

export const DEFAULT_OPENWRT = { iface: 'awg10', routeAll: false };

// Interface name doubles as the firewall zone name, which OpenWrt limits to 11 chars.
export function isValidIfaceName(name) {
  return /^[a-z][a-z0-9_]{0,10}$/.test(String(name || ''));
}

const q = (v) => `'${String(v).replace(/'/g, `'\\''`)}'`;

/**
 * @param reg  registration ({ privateKey, peerPublicKey, v4, v6 })
 * @param s    page settings (same object buildConfig takes)
 * @param o    { iface, routeAll }
 */
export function buildUci(reg, s, o = DEFAULT_OPENWRT) {
  const iface = o.iface;
  if (!isValidIfaceName(iface)) throw new Error('имя интерфейса: латинские строчные буквы, цифры и _, до 11 символов, начинается с буквы');

  // Take the final values from the same builder the .conf uses, so both always agree.
  const conf = buildConfig(reg, s);
  const get = (key) => {
    const m = conf.match(new RegExp(`^${key} = (.*)$`, 'm'));
    return m ? m[1] : '';
  };
  const list = (key) => get(key).split(',').map((x) => x.trim()).filter(Boolean);
  const endpoint = get('Endpoint').match(/^\[?(.+?)\]?:(\d+)$/);

  const n = `network.${iface}`;
  const peer = `network.${iface}_peer`;
  const zone = `firewall.${iface}_zone`;
  const fwd = `firewall.${iface}_fwd`;
  const L = [];

  L.push('# AmneziaWG WARP для OpenWrt.');
  L.push('# Нужны пакеты kmod-amneziawg, amneziawg-tools и luci-proto-amneziawg.');
  L.push('# Повторный запуск перезаписывает эти же секции.');
  L.push(`uci -q delete ${n}`, `uci -q delete ${peer}`, `uci -q delete ${zone}`, `uci -q delete ${fwd}`);
  L.push('');
  L.push(`uci set ${n}=interface`);
  L.push(`uci set ${n}.proto='amneziawg'`);
  L.push(`uci set ${n}.private_key=${q(get('PrivateKey'))}`);
  for (const a of list('Address')) L.push(`uci add_list ${n}.addresses=${q(a)}`);
  L.push(`uci set ${n}.mtu=${q(get('MTU'))}`);
  for (const k of ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']) {
    L.push(`uci set ${n}.awg_${k.toLowerCase()}=${q(get(k))}`);
  }
  if (get('I1')) L.push(`uci set ${n}.awg_i1=${q(get('I1'))}`);
  // With routeAll the host route to the endpoint must stay, or traffic to the
  // endpoint itself would loop into the tunnel.
  if (!o.routeAll) L.push(`uci set ${n}.nohostroute='1'`);
  L.push('');
  L.push(`uci set ${peer}=amneziawg_${iface}`);
  L.push(`uci set ${peer}.description='Cloudflare WARP'`);
  L.push(`uci set ${peer}.public_key=${q(get('PublicKey'))}`);
  if (endpoint) {
    L.push(`uci set ${peer}.endpoint_host=${q(endpoint[1])}`);
    L.push(`uci set ${peer}.endpoint_port=${q(endpoint[2])}`);
  }
  if (get('PersistentKeepalive')) L.push(`uci set ${peer}.persistent_keepalive=${q(get('PersistentKeepalive'))}`);
  for (const a of list('AllowedIPs')) L.push(`uci add_list ${peer}.allowed_ips=${q(a)}`);
  L.push(`uci set ${peer}.route_allowed_ips='${o.routeAll ? 1 : 0}'`);
  L.push('');
  L.push(`uci set ${zone}=zone`);
  L.push(`uci set ${zone}.name=${q(iface)}`);
  L.push(`uci add_list ${zone}.network=${q(iface)}`);
  L.push(`uci set ${zone}.input='REJECT'`);
  L.push(`uci set ${zone}.output='ACCEPT'`);
  L.push(`uci set ${zone}.forward='REJECT'`);
  L.push(`uci set ${zone}.masq='1'`);
  L.push(`uci set ${zone}.mtu_fix='1'`);
  if (!s.ipv6) L.push(`uci set ${zone}.family='ipv4'`);
  L.push(`uci set ${fwd}=forwarding`);
  L.push(`uci set ${fwd}.src='lan'`);
  L.push(`uci set ${fwd}.dest=${q(iface)}`);
  L.push('');
  L.push('uci commit network');
  L.push('uci commit firewall');
  L.push('/etc/init.d/network reload');
  L.push('/etc/init.d/firewall reload');
  return L.join('\n') + '\n';
}
