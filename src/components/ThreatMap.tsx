import { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

interface MapIP {
  ip: string;
  lat: number;
  lon: number;
  hosts: string[];
  ports: number[];
  cves: string[];
  org: string;
  cloud: string | null;
  country: string;
  city: string;
}

interface ThreatMapProps {
  ips: Record<string, any>;
}

const CDN_PROVIDERS = ['Cloudflare', 'Akamai', 'Fastly', 'AWS CloudFront'];

export default function ThreatMap({ ips }: ThreatMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  const leafletMap = useRef<L.Map | null>(null);

  useEffect(() => {
    if (!mapRef.current) return;
    if (leafletMap.current) { leafletMap.current.remove(); leafletMap.current = null; }

    const map = L.map(mapRef.current, { zoomControl: true, attributionControl: false }).setView([20, 0], 2);
    leafletMap.current = map;

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 19,
    }).addTo(map);

    const markers: MapIP[] = [];
    Object.entries(ips).forEach(([ip, data]: [string, any]) => {
      if (!data.geo?.lat || !data.geo?.lon) return;
      markers.push({
        ip,
        lat: data.geo.lat,
        lon: data.geo.lon,
        hosts: data.hosts || [],
        ports: data.ports || [],
        cves: data.cves || [],
        org: data.geo?.org || '',
        cloud: data.cloud || null,
        country: data.geo?.country || '',
        city: data.geo?.city || '',
      });
    });

    markers.forEach(m => {
      const hasCVE = m.cves.length > 0;
      const hasDangerousPorts = m.ports.some(p => [3306, 5432, 27017, 6379, 9200, 3389, 2375, 11211].includes(p));
      const isCDN = m.cloud && CDN_PROVIDERS.includes(m.cloud);
      
      const color = (hasCVE || hasDangerousPorts) ? '#e53e3e' : isCDN ? '#48bb78' : '#cc9900';
      const radius = Math.min(8 + m.cves.length * 2 + m.ports.length * 0.5, 20);

      const circle = L.circleMarker([m.lat, m.lon], {
        radius,
        fillColor: color,
        color: color,
        weight: 1,
        opacity: 0.9,
        fillOpacity: 0.6,
      }).addTo(map);

      const popupHTML = `
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#e0e0e0;background:#1a1a1a;padding:8px;border-radius:6px;min-width:200px;">
          <div style="font-weight:700;color:${color};margin-bottom:4px;">${m.ip}</div>
          <div style="color:#999;font-size:9px;">${m.city}${m.city && m.country ? ', ' : ''}${m.country}${m.org ? ' · ' + m.org : ''}</div>
          ${m.cloud ? `<div style="color:#48bb78;font-size:9px;margin-top:2px;">☁ ${m.cloud}</div>` : ''}
          ${m.hosts.length ? `<div style="margin-top:4px;font-size:9px;color:#aaa;">Hosts: ${m.hosts.slice(0, 5).join(', ')}${m.hosts.length > 5 ? ' +' + (m.hosts.length - 5) + ' more' : ''}</div>` : ''}
          ${m.ports.length ? `<div style="margin-top:3px;font-size:9px;">Ports: <span style="color:#cc9900;">${m.ports.slice(0, 10).join(', ')}</span></div>` : ''}
          ${m.cves.length ? `<div style="margin-top:3px;font-size:9px;">CVEs: <span style="color:#e53e3e;">${m.cves.length}</span></div>` : ''}
          <div style="margin-top:5px;display:flex;gap:4px;">
            <a href="https://www.shodan.io/host/${m.ip}" target="_blank" style="color:#cc9900;font-size:9px;text-decoration:none;">Shodan</a>
            <a href="https://ipinfo.io/${m.ip}" target="_blank" style="color:#cc9900;font-size:9px;text-decoration:none;">IPInfo</a>
          </div>
        </div>
      `;
      circle.bindPopup(popupHTML, { className: 'dark-popup' });
    });

    if (markers.length > 0) {
      const bounds = L.latLngBounds(markers.map(m => [m.lat, m.lon] as [number, number]));
      map.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
    }

    return () => { if (leafletMap.current) { leafletMap.current.remove(); leafletMap.current = null; } };
  }, [ips]);

  const ipList = Object.entries(ips).filter(([, d]: [string, any]) => d.geo?.lat).map(([ip, d]: [string, any]) => ({
    ip, city: d.geo?.city || '', country: d.geo?.country || '', org: d.geo?.org || '',
    ports: d.ports || [], cves: d.cves || [], cloud: d.cloud || '', hosts: d.hosts || [],
  }));

  return (
    <div>
      <div ref={mapRef} style={{ height: '400px', borderRadius: '12px', overflow: 'hidden', border: '1px solid hsla(38,92%,50%,0.15)' }} />
      {ipList.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-xs">
            <thead><tr className="text-muted-foreground text-left border-b border-border">
              <th className="pb-2 text-[9px] font-bold tracking-wider uppercase">IP</th>
              <th className="pb-2 text-[9px] font-bold tracking-wider uppercase">Location</th>
              <th className="pb-2 text-[9px] font-bold tracking-wider uppercase">Org</th>
              <th className="pb-2 text-[9px] font-bold tracking-wider uppercase">Cloud</th>
              <th className="pb-2 text-[9px] font-bold tracking-wider uppercase">Ports</th>
              <th className="pb-2 text-[9px] font-bold tracking-wider uppercase">CVEs</th>
              <th className="pb-2 text-[9px] font-bold tracking-wider uppercase">Hosts</th>
            </tr></thead>
            <tbody>{ipList.map((m, i) => (
              <tr key={i} className="border-t border-white/[0.035] hover:bg-primary/[0.025]">
                <td className="py-1.5 font-mono text-[11px]">{m.ip}</td>
                <td className="py-1.5 text-muted-foreground text-[10px]">{m.city}{m.city && m.country ? ', ' : ''}{m.country}</td>
                <td className="py-1.5 text-muted-foreground text-[10px] truncate max-w-[120px]">{m.org || '—'}</td>
                <td className="py-1.5">{m.cloud ? <span className="text-[9px] px-1.5 py-0.5 bg-[hsl(var(--green))]/10 rounded text-[hsl(var(--green))]">{m.cloud}</span> : '—'}</td>
                <td className="py-1.5 text-primary text-[10px]">{m.ports.length ? m.ports.slice(0, 8).join(', ') : '—'}</td>
                <td className="py-1.5">{m.cves.length ? <span className="text-destructive font-semibold">{m.cves.length}</span> : '—'}</td>
                <td className="py-1.5 text-muted-foreground text-[10px] truncate max-w-[150px]">{m.hosts.slice(0, 3).join(', ')}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      <div className="mt-3 flex gap-4 text-[9px] text-muted-foreground">
        <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-full bg-destructive/80" /> CVE/Dangerous Ports</span>
        <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-full bg-[hsl(var(--green))]/80" /> CDN Edge</span>
        <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-full bg-primary/80" /> Normal Host</span>
      </div>
    </div>
  );
}
