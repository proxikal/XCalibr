import { defineBackground } from 'wxt/sandbox';
import { updateState } from '../shared/state';

export default defineBackground(() => {
  chrome.commands.onCommand.addListener(async (command) => {
    if (command !== 'toggle-xcalibr-visibility') return;
    await updateState((current) => ({
      ...current,
      isVisible: !current.isVisible
    }));
  });

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === 'xcalibr-fetch-robots') {
      const run = async () => {
        const tabId = sender.tab?.id;
        if (typeof tabId !== 'number') {
          sendResponse({ error: 'No active tab available.' });
          return;
        }
        const tab = await chrome.tabs.get(tabId);
        const url = tab.url;
        if (!url) {
          sendResponse({ error: 'Unable to resolve tab URL.' });
          return;
        }
        const origin = new URL(url).origin;
        const response = await fetch(`${origin}/robots.txt`, {
          redirect: 'follow'
        });
        const content = await response.text();
        sendResponse({
          url: `${origin}/robots.txt`,
          content,
          updatedAt: Date.now()
        });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Failed to fetch robots.txt.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-fetch-headers') {
      const run = async () => {
        const tabId = sender.tab?.id;
        if (typeof tabId !== 'number') {
          sendResponse({ error: 'No active tab available.' });
          return;
        }
        const tab = await chrome.tabs.get(tabId);
        const url = tab.url;
        if (!url) {
          sendResponse({ error: 'Unable to resolve tab URL.' });
          return;
        }
        const response = await fetch(url, { redirect: 'follow' });
        const headers = Array.from(response.headers.entries()).map(
          ([name, value]) => ({ name, value })
        );
        sendResponse({
          url,
          status: response.status,
          headers,
          updatedAt: Date.now()
        });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Failed to fetch headers.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-payload-replay') {
      const run = async () => {
        const payload = message.payload as {
          url: string;
          method: string;
          headers: { name: string; value: string }[];
          body: string;
          includeCredentials?: boolean;
          followRedirects?: boolean;
        };

        const requestBody = payload.method === 'GET' || payload.method === 'HEAD' ? undefined : payload.body;
        const requestSize = new TextEncoder().encode(
          `${payload.method} ${payload.url}\n${payload.headers.map(h => `${h.name}: ${h.value}`).join('\n')}\n\n${requestBody || ''}`
        ).length;

        const startTime = performance.now();
        const response = await fetch(payload.url, {
          method: payload.method,
          headers: Object.fromEntries(
            payload.headers.map((header) => [header.name, header.value])
          ),
          body: requestBody,
          credentials: payload.includeCredentials ? 'include' : 'omit',
          redirect: payload.followRedirects !== false ? 'follow' : 'manual'
        });
        const latencyMs = performance.now() - startTime;

        const responseBody = await response.text();
        const responseSize = new TextEncoder().encode(responseBody).length;
        const responseHeaders = Array.from(response.headers.entries()).map(
          ([name, value]) => ({ name, value })
        );

        // Check for redirects (if we followed them)
        const wasRedirected = response.redirected;
        const finalUrl = response.url !== payload.url ? response.url : undefined;

        sendResponse({
          responseStatus: response.status,
          responseHeaders,
          responseBody,
          latencyMs,
          requestSize,
          responseSize,
          redirectCount: wasRedirected ? 1 : 0,
          finalUrl,
          error: undefined
        });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Request failed.'
        });
      });
      return true;
    }

    // NOTE: xcalibr-cors-check handler was removed due to MV3 limitations.
    // In Manifest V3, cross-origin CORS header inspection is severely limited.
    // Users should use browser DevTools or proxy tools for CORS analysis.

    if (message?.type === 'xcalibr-couchdb-fetch') {
      const run = async () => {
        const { url } = message.payload as { url: string };
        const response = await fetch(url, { method: 'GET' });
        const text = await response.text();
        sendResponse({
          output: text,
          error: response.ok ? '' : `Request failed (${response.status})`
        });
      };

      run().catch((error) => {
        sendResponse({
          output: '',
          error: error instanceof Error ? error.message : 'Fetch failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-http-request') {
      const run = async () => {
        const payload = message.payload as {
          url: string;
          method: string;
          headers?: Record<string, string>;
          body?: string;
        };
        const response = await fetch(payload.url, {
          method: payload.method,
          headers: payload.headers,
          body:
            payload.method === 'GET' || payload.method === 'HEAD'
              ? undefined
              : payload.body
        });
        const text = await response.text();
        sendResponse({
          status: response.status,
          statusText: response.statusText,
          headers: Array.from(response.headers.entries()).map(([name, value]) => ({
            name,
            value
          })),
          body: text
        });
      };

      run().catch((error) => {
        sendResponse({
          status: 0,
          statusText: '',
          headers: [],
          body: '',
          error: error instanceof Error ? error.message : 'Request failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-whois-lookup') {
      const run = async () => {
        const { domain } = message.payload as { domain: string };

        // Extract the base domain (remove www. prefix and any path)
        let cleanDomain = domain.toLowerCase().trim();
        if (cleanDomain.includes('://')) {
          cleanDomain = new URL(cleanDomain).hostname;
        }
        cleanDomain = cleanDomain.replace(/^www\./, '');

        // Get the TLD to determine the RDAP server
        const parts = cleanDomain.split('.');
        const tld = parts[parts.length - 1];

        // Common RDAP bootstrap servers by TLD
        const rdapServers: Record<string, string> = {
          com: 'https://rdap.verisign.com/com/v1/domain/',
          net: 'https://rdap.verisign.com/net/v1/domain/',
          org: 'https://rdap.publicinterestregistry.org/rdap/domain/',
          io: 'https://rdap.nic.io/domain/',
          co: 'https://rdap.nic.co/domain/',
          dev: 'https://rdap.nic.google/domain/',
          app: 'https://rdap.nic.google/domain/',
          me: 'https://rdap.nic.me/domain/',
          info: 'https://rdap.afilias.net/rdap/info/domain/',
          biz: 'https://rdap.nic.biz/domain/'
        };

        const rdapUrl = rdapServers[tld]
          ? `${rdapServers[tld]}${cleanDomain}`
          : `https://rdap.org/domain/${cleanDomain}`;

        const response = await fetch(rdapUrl, {
          headers: { Accept: 'application/rdap+json' }
        });

        if (!response.ok) {
          throw new Error(`RDAP lookup failed: ${response.status} ${response.statusText}`);
        }

        const rdap = await response.json();

        // Parse the RDAP response
        const result: {
          domain: string;
          status: string;
          registrar: string;
          registrant: string;
          createdDate: string;
          expiresDate: string;
          updatedDate: string;
          nameservers: string[];
        } = {
          domain: rdap.ldhName || cleanDomain,
          status: Array.isArray(rdap.status) ? rdap.status.join(', ') : 'Unknown',
          registrar: '',
          registrant: '',
          createdDate: '',
          expiresDate: '',
          updatedDate: '',
          nameservers: []
        };

        // Parse events for dates
        if (Array.isArray(rdap.events)) {
          for (const event of rdap.events) {
            if (event.eventDate) {
              const date = new Date(event.eventDate).toLocaleDateString();
              if (event.eventAction === 'registration') {
                result.createdDate = date;
              } else if (event.eventAction === 'expiration') {
                result.expiresDate = date;
              } else if (event.eventAction === 'last changed') {
                result.updatedDate = date;
              }
            }
          }
        }

        // Parse entities for registrar/registrant
        if (Array.isArray(rdap.entities)) {
          for (const entity of rdap.entities) {
            const vcardArray = entity.vcardArray;
            if (Array.isArray(vcardArray) && vcardArray[1]) {
              const fnEntry = vcardArray[1].find(
                (v: unknown) => Array.isArray(v) && v[0] === 'fn'
              );
              const name = fnEntry ? fnEntry[3] : undefined;
              if (Array.isArray(entity.roles)) {
                if (entity.roles.includes('registrar') && name) {
                  result.registrar = name;
                }
                if (entity.roles.includes('registrant') && name) {
                  result.registrant = name;
                }
              }
            }
          }
        }

        // Parse nameservers
        if (Array.isArray(rdap.nameservers)) {
          result.nameservers = rdap.nameservers
            .map((ns: { ldhName?: string }) => ns.ldhName)
            .filter(Boolean);
        }

        sendResponse({ result });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'WHOIS lookup failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-dns-lookup') {
      const run = async () => {
        const { domain } = message.payload as { domain: string };

        // Clean domain
        let cleanDomain = domain.toLowerCase().trim();
        if (cleanDomain.includes('://')) {
          cleanDomain = new URL(cleanDomain).hostname;
        }
        cleanDomain = cleanDomain.replace(/^www\./, '');

        // Use public DNS-over-HTTPS API (Cloudflare)
        const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
        const records: {
          type: string;
          name: string;
          value: string;
          ttl?: number;
          priority?: number;
        }[] = [];

        // Fetch all record types in parallel
        const responses = await Promise.allSettled(
          recordTypes.map(async (type) => {
            const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=${type}`;
            const response = await fetch(url, {
              headers: { Accept: 'application/dns-json' }
            });
            if (!response.ok) return null;
            return response.json();
          })
        );

        // Parse responses
        for (let i = 0; i < responses.length; i++) {
          const result = responses[i];
          if (result.status === 'fulfilled' && result.value?.Answer) {
            for (const answer of result.value.Answer) {
              const record: {
                type: string;
                name: string;
                value: string;
                ttl?: number;
                priority?: number;
              } = {
                type: recordTypes[i],
                name: answer.name?.replace(/\.$/, '') || cleanDomain,
                value: answer.data?.replace(/\.$/, '') || '',
                ttl: answer.TTL
              };

              // Parse MX priority
              if (recordTypes[i] === 'MX' && typeof answer.data === 'string') {
                const parts = answer.data.split(' ');
                if (parts.length >= 2) {
                  record.priority = parseInt(parts[0], 10);
                  record.value = parts.slice(1).join(' ').replace(/\.$/, '');
                }
              }

              records.push(record);
            }
          }
        }

        if (records.length === 0) {
          throw new Error('No DNS records found');
        }

        sendResponse({ records });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'DNS lookup failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-reverse-ip-lookup') {
      const run = async () => {
        const { ip } = message.payload as { ip: string };

        // Validate IP format
        const cleanIp = ip.trim();
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){0,6}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$/;

        if (!ipv4Pattern.test(cleanIp) && !ipv6Pattern.test(cleanIp)) {
          throw new Error('Invalid IP address format');
        }

        // Use HackerTarget reverse IP API (free, no auth required)
        const url = `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(cleanIp)}`;
        const response = await fetch(url);

        if (!response.ok) {
          throw new Error(`Reverse IP lookup failed: ${response.status}`);
        }

        const text = await response.text();

        // Check for API error
        if (text.startsWith('error')) {
          throw new Error(text);
        }

        // Parse domains (one per line)
        const domains = text
          .split('\n')
          .map(d => d.trim())
          .filter(d => d && !d.startsWith('error') && d.includes('.'));

        if (domains.length === 0) {
          throw new Error('No domains found for this IP');
        }

        sendResponse({ domains });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Reverse IP lookup failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-username-search') {
      const run = async () => {
        const { username } = message.payload as { username: string };

        // Define platforms to check
        const platforms = [
          { name: 'Twitter', url: `https://twitter.com/${username}` },
          { name: 'GitHub', url: `https://github.com/${username}` },
          { name: 'Reddit', url: `https://reddit.com/user/${username}` },
          { name: 'Instagram', url: `https://instagram.com/${username}` },
          { name: 'LinkedIn', url: `https://linkedin.com/in/${username}` }
        ];

        type PlatformResult = {
          platform: string;
          url: string;
          status: 'found' | 'not_found' | 'error';
          statusCode: number;
          error?: string;
        };

        const results: PlatformResult[] = [];

        // Check each platform
        for (const platform of platforms) {
          try {
            const response = await fetch(platform.url, {
              method: 'HEAD',
              redirect: 'manual'
            });

            // Determine status based on response
            let status: 'found' | 'not_found' | 'error';
            if (response.status === 200 || response.status === 301 || response.status === 302) {
              status = 'found';
            } else if (response.status === 404) {
              status = 'not_found';
            } else if (response.status === 403 || response.status === 429) {
              status = 'error';
            } else {
              status = response.status >= 400 ? 'not_found' : 'found';
            }

            results.push({
              platform: platform.name,
              url: platform.url,
              status,
              statusCode: response.status,
              error: status === 'error' ? `HTTP ${response.status}` : undefined
            });
          } catch (error) {
            results.push({
              platform: platform.name,
              url: platform.url,
              status: 'error',
              statusCode: 0,
              error: error instanceof Error ? error.message : 'Connection failed'
            });
          }
        }

        sendResponse({ results });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Username search failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-email-breach-check') {
      const run = async () => {
        const { email } = message.payload as { email: string };

        // Use the Have I Been Pwned API (v3)
        // Note: This requires an API key for production use
        // For now, we'll use a free alternative or mock data
        const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;

        try {
          const response = await fetch(url, {
            method: 'GET',
            headers: {
              'User-Agent': 'XCalibr-Extension',
              'hibp-api-key': '' // API key would go here for production
            }
          });

          if (response.status === 404) {
            // No breaches found - email is safe
            sendResponse({ breaches: [] });
            return;
          }

          if (response.status === 401) {
            throw new Error('API key required. HIBP now requires a paid API key.');
          }

          if (response.status === 429) {
            throw new Error('Rate limit exceeded. Please try again later.');
          }

          if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
          }

          type HibpBreach = {
            Name: string;
            Domain: string;
            BreachDate: string;
            AddedDate: string;
            PwnCount: number;
            Description: string;
            DataClasses: string[];
            IsVerified: boolean;
            IsSensitive: boolean;
          };

          const data = (await response.json()) as HibpBreach[];

          const breaches = data.map((b) => ({
            name: b.Name,
            domain: b.Domain,
            breachDate: b.BreachDate,
            addedDate: b.AddedDate,
            pwnCount: b.PwnCount,
            description: b.Description.replace(/<[^>]*>/g, ''), // Strip HTML
            dataClasses: b.DataClasses,
            isVerified: b.IsVerified,
            isSensitive: b.IsSensitive
          }));

          sendResponse({ breaches });
        } catch (error) {
          // If HIBP fails due to API key requirement, return a helpful message
          if (error instanceof Error && error.message.includes('API key')) {
            sendResponse({
              error: 'Email breach checking requires a Have I Been Pwned API key. Visit haveibeenpwned.com/API/Key to get one.'
            });
          } else {
            throw error;
          }
        }
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Email breach check failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-ssl-cert-decode') {
      const run = async () => {
        const { domain } = message.payload as { domain: string };

        // Clean domain
        let cleanDomain = domain.toLowerCase().trim();
        if (cleanDomain.includes('://')) {
          cleanDomain = new URL(cleanDomain).hostname;
        }
        cleanDomain = cleanDomain.replace(/^www\./, '');

        // Use crt.sh API to get certificate information
        // This provides certificate transparency logs
        const url = `https://crt.sh/?q=${encodeURIComponent(cleanDomain)}&output=json`;

        const response = await fetch(url, {
          headers: { Accept: 'application/json' }
        });

        if (!response.ok) {
          throw new Error(`Failed to fetch certificate: ${response.status}`);
        }

        const certs = (await response.json()) as Array<{
          issuer_ca_id: number;
          issuer_name: string;
          common_name: string;
          name_value: string;
          id: number;
          entry_timestamp: string;
          not_before: string;
          not_after: string;
          serial_number: string;
        }>;

        if (!certs || certs.length === 0) {
          throw new Error('No certificates found for this domain');
        }

        // Get the most recent certificate
        const latestCert = certs[0];

        // Parse issuer name
        const issuerParts: Record<string, string> = {};
        latestCert.issuer_name.split(',').forEach((part) => {
          const [key, value] = part.trim().split('=');
          if (key && value) {
            issuerParts[key.trim()] = value.trim();
          }
        });

        // Calculate expiry
        const notAfter = new Date(latestCert.not_after);
        const now = new Date();
        const daysUntilExpiry = Math.floor(
          (notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        );

        // Parse SANs from name_value
        const sans = latestCert.name_value
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean);

        const certificate = {
          subject: {
            CN: latestCert.common_name,
            O: undefined,
            C: undefined
          },
          issuer: {
            CN: issuerParts['CN'] || issuerParts['O'] || 'Unknown',
            O: issuerParts['O'],
            C: issuerParts['C']
          },
          validFrom: latestCert.not_before,
          validTo: latestCert.not_after,
          serialNumber: latestCert.serial_number,
          fingerprint: `ID: ${latestCert.id}`,
          signatureAlgorithm: 'See crt.sh for details',
          keySize: undefined,
          sans,
          isExpired: daysUntilExpiry < 0,
          daysUntilExpiry
        };

        sendResponse({ certificate });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'SSL certificate decode failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-subdomain-find') {
      const run = async () => {
        const { domain } = message.payload as { domain: string };

        // Clean domain
        let cleanDomain = domain.toLowerCase().trim();
        if (cleanDomain.includes('://')) {
          cleanDomain = new URL(cleanDomain).hostname;
        }
        cleanDomain = cleanDomain.replace(/^www\./, '');

        // Use crt.sh API for subdomain enumeration via certificate transparency
        const url = `https://crt.sh/?q=%25.${encodeURIComponent(cleanDomain)}&output=json`;

        const response = await fetch(url, {
          headers: { Accept: 'application/json' }
        });

        if (!response.ok) {
          throw new Error(`Failed to fetch subdomains: ${response.status}`);
        }

        const certs = (await response.json()) as Array<{
          name_value: string;
          common_name: string;
        }>;

        if (!certs || certs.length === 0) {
          sendResponse({ subdomains: [] });
          return;
        }

        // Extract unique subdomains from certificate data
        const subdomainSet = new Set<string>();

        for (const cert of certs) {
          // Add common_name
          if (cert.common_name) {
            const cn = cert.common_name.toLowerCase().trim();
            if (cn.endsWith(`.${cleanDomain}`) || cn === cleanDomain) {
              subdomainSet.add(cn);
            }
          }

          // Add name_value (can contain multiple SANs)
          if (cert.name_value) {
            const names = cert.name_value.split('\n');
            for (const name of names) {
              const trimmed = name.toLowerCase().trim();
              if (trimmed && !trimmed.startsWith('*') &&
                  (trimmed.endsWith(`.${cleanDomain}`) || trimmed === cleanDomain)) {
                subdomainSet.add(trimmed);
              }
            }
          }
        }

        const subdomains = Array.from(subdomainSet).sort();
        sendResponse({ subdomains });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Subdomain search failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-wayback-search') {
      const run = async () => {
        const { url } = message.payload as { url: string };

        // Normalize URL
        let normalizedUrl = url.trim();
        if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
          normalizedUrl = 'https://' + normalizedUrl;
        }

        // Use Wayback Machine CDX API
        const apiUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(normalizedUrl)}&output=json&fl=timestamp,original,statuscode,mimetype&collapse=timestamp:6&limit=500`;

        const response = await fetch(apiUrl, {
          headers: { Accept: 'application/json' }
        });

        if (!response.ok) {
          throw new Error(`Failed to fetch from Wayback Machine: ${response.status}`);
        }

        const data = (await response.json()) as string[][];

        if (!data || data.length <= 1) {
          // First row is headers, so <= 1 means no results
          sendResponse({ snapshots: [] });
          return;
        }

        // Skip header row and map to objects
        const snapshots = data.slice(1).map((row) => ({
          timestamp: row[0],
          original: row[1],
          statuscode: row[2],
          mimetype: row[3]
        }));

        // Sort by timestamp descending (newest first)
        snapshots.sort((a, b) => b.timestamp.localeCompare(a.timestamp));

        sendResponse({ snapshots });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Wayback Machine search failed.'
        });
      });
      return true;
    }

    if (message?.type !== 'xcalibr-inject-code') return;

    const { scope, code } = message.payload as {
      scope: 'current' | 'all';
      code: string;
    };

    const injectCssIntoTab = async (tabId: number) => {
      await chrome.scripting.insertCSS({
        target: { tabId },
        css: code
      });
    };

    const run = async () => {
      if (scope === 'current') {
        const tabId = sender.tab?.id;
        if (typeof tabId === 'number') {
          await injectCssIntoTab(tabId);
        }
        sendResponse({ ok: true });
        return;
      }

      const tabs = await chrome.tabs.query({});
      await Promise.allSettled(
        tabs
          .map((tab) => tab.id)
          .filter((tabId): tabId is number => typeof tabId === 'number')
          .map((tabId) => injectCssIntoTab(tabId))
      );
      sendResponse({ ok: true });
    };

    run().catch(() => sendResponse({ ok: false }));
    return true;
  });
});
