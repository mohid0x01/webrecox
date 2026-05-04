/* WebRecox — Scan profile presets that drive module set, concurrency, timeout. */

export type ProfileId = 'quick' | 'deep' | 'stealth';

export interface ProfileConfig {
  id: ProfileId;
  label: string;
  description: string;
  /** Source IDs allowed for this profile. `*` means all. */
  allowedSources: string[] | '*';
  /** Promise-pool concurrency for sub/endpoint phases. */
  concurrency: number;
  /** Per-fetch timeout multiplier (default 1.0). */
  timeoutMultiplier: number;
  /** Optional artificial delay between requests (stealth). */
  jitterMs: number;
  /** Force proxy-only (skip direct fetch). */
  proxyOnly: boolean;
}

export const PROFILES: Record<ProfileId, ProfileConfig> = {
  quick: {
    id: 'quick',
    label: 'Quick (2min)',
    description: 'Fast pass — top sources, high concurrency, short timeout',
    allowedSources: [
      'crt', 'ht', 'jldc', 'rapiddns', 'certspot', 'urlscan',
      'wb', 'sitemap', 'robotstxt',
      'jsfind', 'cors', 'httpheaders', 'geo', 'rdap',
    ],
    concurrency: 12,
    timeoutMultiplier: 0.5,
    jitterMs: 0,
    proxyOnly: false,
  },
  deep: {
    id: 'deep',
    label: 'Deep (20min)',
    description: 'All sources & all modules with normal timeouts',
    allowedSources: '*',
    concurrency: 8,
    timeoutMultiplier: 1.0,
    jitterMs: 0,
    proxyOnly: false,
  },
  stealth: {
    id: 'stealth',
    label: 'Stealth',
    description: 'Passive sources only, single-thread, randomized delays',
    allowedSources: [
      'crt', 'jldc', 'certspot', 'otxsub', 'threatminer', 'wbsubs',
      'wb', 'otxurl', 'cc', 'sitemap', 'robotstxt',
      'rdap', 'otxintel', 'hibp', 'leakix',
    ],
    concurrency: 1,
    timeoutMultiplier: 1.5,
    jitterMs: 800,
    proxyOnly: true,
  },
};

export function profileAllowsSource(profile: ProfileId, sourceId: string): boolean {
  const p = PROFILES[profile];
  if (p.allowedSources === '*') return true;
  return p.allowedSources.includes(sourceId);
}

/** Apply a profile preset on top of an existing source toggle map. */
export function applyProfileToSources(
  profile: ProfileId,
  sources: Record<string, boolean>,
): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const id of Object.keys(sources)) {
    out[id] = sources[id] && profileAllowsSource(profile, id);
  }
  return out;
}
