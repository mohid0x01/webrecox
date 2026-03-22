export function exportCSV(data: Record<string, any>[], filename: string) {
  if (!data.length) return;
  const headers = Object.keys(data[0]);
  const csv = [
    headers.join(','),
    ...data.map(row => headers.map(h => `"${String(row[h] || '').replace(/"/g, "'")}"` ).join(','))
  ].join('\n');
  download(csv, filename + '.csv', 'text/csv');
}

export function exportJSON(data: any, filename: string) {
  download(JSON.stringify(data, null, 2), filename + '.json', 'application/json');
}

export function exportTXT(lines: string[], filename: string) {
  download(lines.join('\n'), filename + '.txt', 'text/plain');
}

export function exportPDF(title: string, sections: { heading: string; content: string }[]) {
  // Generate a printable HTML and open in new tab for PDF
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${title}</title>
<style>
body{font-family:'JetBrains Mono',monospace;background:#fff;color:#111;padding:40px;font-size:12px;line-height:1.8;}
h1{font-size:22px;border-bottom:3px solid #d97706;padding-bottom:10px;margin-bottom:20px;display:flex;align-items:center;gap:12px;}
h1 img{width:36px;height:36px;border-radius:50%;}
h2{font-size:14px;color:#d97706;margin:20px 0 8px;border-bottom:1px solid #eee;padding-bottom:4px;}
pre{background:#f5f5f5;padding:12px;border-radius:6px;white-space:pre-wrap;word-break:break-all;font-size:11px;}
.meta{color:#666;font-size:11px;margin-bottom:20px;}
@media print{body{padding:20px;}}
</style></head><body>
<h1><img src="https://github.com/mohidqx.png" alt="logo"/>${title}</h1>
<div class="meta">Generated: ${new Date().toISOString()} | TeamCyberOps Recon | github.com/mohidqx</div>
${sections.map(s => `<h2>${s.heading}</h2><pre>${escapeHtml(s.content)}</pre>`).join('')}
<hr style="margin-top:30px;border:none;border-top:1px solid #ddd"/>
<div class="meta" style="text-align:center;margin-top:10px">© TeamCyberOps — For authorized security testing only — github.com/mohidqx</div>
</body></html>`;
  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); setTimeout(() => win.print(), 500); }
}

function download(content: string, filename: string, type: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function escapeHtml(s: string) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
