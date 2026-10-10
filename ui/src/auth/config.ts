// Runtime settings: /config.json next to index.html, so one build runs in
// any environment. Missing keys fall back to the lab defaults.
export interface UiConfig {
  oidcAuthority: string;
  oidcClientId: string;
}

export const defaultConfig: UiConfig = {
  oidcAuthority: 'http://127.0.0.1:18180/realms/strata',
  oidcClientId: 'strata-ui',
};

export async function loadConfig(fetchFn: typeof fetch = fetch): Promise<UiConfig> {
  try {
    const res = await fetchFn('/config.json', { cache: 'no-store' });
    if (!res.ok) return defaultConfig;
    const body = (await res.json()) as Partial<UiConfig>;
    return {
      oidcAuthority: typeof body.oidcAuthority === 'string' ? body.oidcAuthority : defaultConfig.oidcAuthority,
      oidcClientId: typeof body.oidcClientId === 'string' ? body.oidcClientId : defaultConfig.oidcClientId,
    };
  } catch {
    return defaultConfig;
  }
}
