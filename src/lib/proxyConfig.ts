/* WebRecox — Runtime-configurable proxy fallback for CORS-resilient fetches.
   Persisted to localStorage so settings survive reloads. */

export interface ProxyProvider {
  id: string;
  label: string;
  build: (u: string) => string;
}

export const DEFAULT_PROVIDERS: ProxyProvider[] = [
  { id: 'direct',     label: 'Direct (no proxy)',          build: (u) => u },
  { id: 'allorigins', label: 'AllOrigins',                  build: (u) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}` },
  { id: 'corsproxy',  label: 'corsproxy.io',                build: (u) => `https://corsproxy.io/?url=${encodeURIComponent(u)}` },
  { id: 'codetabs',   label: 'codetabs.com',                build: (u) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}` },
  { id: 'thingproxy', label: 'thingproxy.freeboard.io',     build: (u) => `https://thingproxy.freeboard.io/fetch/${u}` },
  { id: 'cors-anywhere', label: 'cors-anywhere (heroku)',   build: (u) => `https://cors-anywhere.herokuapp.com/${u}` },
];

export interface ProxyConfig {
  enabled: boolean;          // master switch — if false, only direct fetch is used
  timeoutMs: number;         // per-attempt timeout
  enabledProviders: string[];// ordered list of provider ids
}

const KEY = 'webrecox.proxyConfig.v1';

export const defaultProxyConfig: ProxyConfig = {
  enabled: true,
  timeoutMs: 15000,
  enabledProviders: ['direct', 'allorigins', 'corsproxy', 'codetabs'],
};

let _config: ProxyConfig = (() => {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return { ...defaultProxyConfig, ...JSON.parse(raw) };
  } catch { /* ignore */ }
  return { ...defaultProxyConfig };
})();

export function getProxyConfig(): ProxyConfig { return _config; }

export function setProxyConfig(next: Partial<ProxyConfig>) {
  _config = { ..._config, ...next };
  try { localStorage.setItem(KEY, JSON.stringify(_config)); } catch { /* ignore */ }
}

export function resetProxyConfig() {
  _config = { ...defaultProxyConfig };
  try { localStorage.setItem(KEY, JSON.stringify(_config)); } catch { /* ignore */ }
}

/** Resolved provider list in priority order, honoring `enabled`. */
export function getActiveProviders(): ProxyProvider[] {
  if (!_config.enabled) {
    return DEFAULT_PROVIDERS.filter(p => p.id === 'direct');
  }
  const map = new Map(DEFAULT_PROVIDERS.map(p => [p.id, p]));
  const list: ProxyProvider[] = [];
  for (const id of _config.enabledProviders) {
    const p = map.get(id);
    if (p) list.push(p);
  }
  if (!list.length) list.push(DEFAULT_PROVIDERS[0]);
  return list;
}
