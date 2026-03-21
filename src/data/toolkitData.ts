export interface AuditTool {
  name: string;
  command: string;
  description: string;
  /** If set, this tool triggers a real scan via the edge function */
  scanType?: string;
}

export interface ToolkitCategory {
  key: string;
  label: string;
  icon: string;
  tools: AuditTool[];
}

const createToolkitData = (target: string): ToolkitCategory[] => [
  {
    key: 'domainInventory',
    label: 'Domain Inventory',
    icon: 'Globe',
    tools: [
      { name: 'Subdomain Discovery', command: `subfinder -d ${target} -all`, description: 'Comprehensive mapping of organization-owned web assets via certificate transparency logs.', scanType: 'subdomain_discovery' },
      { name: 'Certificate Analysis', command: `curl -s "https://crt.sh/?q=%25.${target}&output=json"`, description: 'Reviewing public transparency logs for asset verification.', scanType: 'certificate_analysis' },
    ],
  },
  {
    key: 'dnsRecon',
    label: 'DNS Reconnaissance',
    icon: 'Radar',
    tools: [
      { name: 'DNS Record Enumeration', command: `dig ${target} ANY`, description: 'Full DNS record enumeration including A, AAAA, MX, NS, TXT, CNAME, SOA.', scanType: 'dns_lookup' },
      { name: 'WHOIS / RDAP Lookup', command: `whois ${target}`, description: 'Domain registration data, nameservers, and expiry from RDAP.', scanType: 'whois_lookup' },
    ],
  },
  {
    key: 'liveHostDiscovery',
    label: 'Live Host Discovery',
    icon: 'Activity',
    tools: [
      { name: 'HTTP Probe', command: `httpx -u ${target} -status-code`, description: 'Identifying live and responsive hosts with HTTP/HTTPS status codes.', scanType: 'http_probe' },
      { name: 'Security Headers Audit', command: `curl -I https://${target}`, description: 'Analyzing security headers like HSTS, CSP, X-Frame-Options.', scanType: 'security_headers' },
    ],
  },
  {
    key: 'techDetection',
    label: 'Technology Detection',
    icon: 'Cpu',
    tools: [
      { name: 'Tech Stack Fingerprint', command: `wappalyzer https://${target}`, description: 'Detecting web frameworks, CMS, analytics, and CDN technologies.', scanType: 'tech_detection' },
    ],
  },
  {
    key: 'vulnerabilityAssessment',
    label: 'Vulnerability Assessment',
    icon: 'ShieldAlert',
    tools: [
      { name: 'Template-Based Auditing', command: `nuclei -u https://${target} -t cves/`, description: 'Automated scanning for known configuration weaknesses.' },
      { name: 'Storage Security', command: `s3scanner scan --bucket ${target}`, description: 'Verifying permissions on cloud-based object storage.' },
    ],
  },
  {
    key: 'identityVerification',
    label: 'Identity Verification',
    icon: 'Fingerprint',
    tools: [
      { name: 'Token Integrity', command: `python3 -c "import jwt..."`, description: 'Analyzing the robustness of session management implementations.' },
      { name: 'Access Control', command: `curl -s -o /dev/null -w "%{http_code}" https://${target}/admin`, description: 'Testing the strength of authenticated endpoint boundaries.' },
    ],
  },
  {
    key: 'infrastructureReview',
    label: 'Infrastructure Review',
    icon: 'Server',
    tools: [
      { name: 'API Schema Analysis', command: `curl -s https://${target}/graphql?query={__schema{types{name}}}`, description: 'Mapping GraphQL and REST structures for data exposure risks.' },
      { name: 'Cloud Config Audit', command: `kubectl auth can-i --list`, description: 'Validating Kubernetes and Cloud service account permissions.' },
    ],
  },
  {
    key: 'urlCollection',
    label: 'URL Collection',
    icon: 'Link',
    tools: [
      { name: 'Wayback Crawl', command: `waybackurls ${target}`, description: 'Harvesting historical URLs from web archive records.' },
      { name: 'Parameter Mining', command: `paramspider -d ${target}`, description: 'Extracting URL parameters for input vector analysis.' },
    ],
  },
  {
    key: 'directoryBruteforcing',
    label: 'Directory Bruteforcing',
    icon: 'FolderSearch',
    tools: [
      { name: 'Path Discovery', command: `ffuf -u https://${target}/FUZZ -w wordlist.txt`, description: 'Enumerating hidden directories and sensitive file paths.' },
    ],
  },
  {
    key: 'corsTesting',
    label: 'CORS Testing',
    icon: 'ArrowLeftRight',
    tools: [
      { name: 'Origin Policy Check', command: `curl -H "Origin: https://evil.com" -I https://${target}`, description: 'Validating cross-origin resource sharing configurations.' },
    ],
  },
  {
    key: 'takeoverSection',
    label: 'Subdomain Takeover',
    icon: 'AlertTriangle',
    tools: [
      { name: 'Dangling DNS', command: `subjack -w subs.txt -t 100 -ssl`, description: 'Detecting unclaimed DNS records vulnerable to takeover.' },
    ],
  },
  {
    key: 'gitDisclosure',
    label: 'Git Disclosure',
    icon: 'GitBranch',
    tools: [
      { name: 'Repository Exposure', command: `git-dumper https://${target}/.git/`, description: 'Checking for exposed version control repositories.' },
    ],
  },
  {
    key: 'ssrfSection',
    label: 'SSRF Analysis',
    icon: 'Unplug',
    tools: [
      { name: 'Internal Reach', command: `curl "https://${target}/fetch?url=..."`, description: 'Testing server-side request forgery vectors against internal services.' },
    ],
  },
  {
    key: 'lfiSection',
    label: 'Local File Inclusion',
    icon: 'FileWarning',
    tools: [
      { name: 'Path Traversal', command: `curl "https://${target}/page?file=../../etc/passwd"`, description: 'Testing for unauthorized local file access via path traversal.' },
    ],
  },
  {
    key: 'xxeSection',
    label: 'XXE Injection',
    icon: 'Code',
    tools: [
      { name: 'XML Entity Test', command: `curl -X POST -d @xxe.xml https://${target}/api/parse`, description: 'Evaluating XML external entity processing vulnerabilities.' },
    ],
  },
  {
    key: 'sstiSection',
    label: 'Template Injection',
    icon: 'Braces',
    tools: [
      { name: 'SSTI Probe', command: `curl "https://${target}/render?name={{7*7}}"`, description: 'Testing server-side template injection in rendering engines.' },
    ],
  },
  {
    key: 'apiKeySection',
    label: 'API Key Exposure',
    icon: 'KeyRound',
    tools: [
      { name: 'Secret Scanner', command: `trufflehog git https://github.com/${target}`, description: 'Scanning codebases for hardcoded credentials and API keys.' },
    ],
  },
  {
    key: 'wafBypassSection',
    label: 'WAF Bypass',
    icon: 'ShieldOff',
    tools: [
      { name: 'Firewall Evasion', command: `wafw00f https://${target}`, description: 'Identifying and testing web application firewall bypass techniques.' },
    ],
  },
  {
    key: 'cloudSection',
    label: 'Cloud Security',
    icon: 'Cloud',
    tools: [
      { name: 'AWS Enumeration', command: `aws s3 ls s3://${target} --no-sign-request`, description: 'Auditing cloud storage permissions and public access controls.' },
    ],
  },
  {
    key: 'k8sSection',
    label: 'Kubernetes Audit',
    icon: 'Container',
    tools: [
      { name: 'Cluster Policies', command: `kubectl get networkpolicies --all-namespaces`, description: 'Reviewing Kubernetes network policies and RBAC configurations.' },
    ],
  },
  {
    key: 'jwtSection',
    label: 'JWT Security',
    icon: 'Lock',
    tools: [
      { name: 'Token Forgery Test', command: `jwt_tool token.txt -C -d wordlist.txt`, description: 'Assessing JWT signing algorithm strength and key security.' },
    ],
  },
  {
    key: 'osintSection',
    label: 'OSINT Gathering',
    icon: 'Search',
    tools: [
      { name: 'Digital Footprint', command: `theHarvester -d ${target} -b all`, description: 'Collecting publicly available intelligence on the target organization.' },
    ],
  },
  {
    key: 'cveSection',
    label: 'CVE Analysis',
    icon: 'Bug',
    tools: [
      { name: 'Known Exploits', command: `searchsploit ${target}`, description: 'Cross-referencing infrastructure against public vulnerability databases.' },
    ],
  },
  {
    key: 'websocketSection',
    label: 'WebSocket Security',
    icon: 'Plug',
    tools: [
      { name: 'WS Protocol Audit', command: `wscat -c wss://${target}/ws`, description: 'Testing WebSocket handshake security and message injection.' },
    ],
  },
  {
    key: 'aimlSection',
    label: 'AI/ML Security',
    icon: 'Brain',
    tools: [
      { name: 'Model Probing', command: `curl -X POST https://${target}/api/predict`, description: 'Evaluating AI model endpoints for adversarial input vulnerabilities.' },
    ],
  },
];

export default createToolkitData;
