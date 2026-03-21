export interface AuditTool {
  name: string;
  command: string;
  description: string;
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
      { name: 'Subdomain Discovery', command: `subfinder -d ${target} -all`, description: 'Comprehensive mapping of organization-owned web assets.' },
      { name: 'Certificate Analysis', command: `curl -s "https://crt.sh/?q=%25.${target}&output=json" | jq -r '.[].name_value' | sort -u`, description: 'Reviewing public transparency logs for asset verification.' },
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
      { name: 'Token Integrity', command: `python3 -c "import jwt; print(jwt.decode(open('token.txt').read(), options={'verify_signature': False}))"`, description: 'Analyzing the robustness of session management implementations.' },
      { name: 'Access Control', command: `curl -s -o /dev/null -w "%{http_code}" https://${target}/admin`, description: 'Testing the strength of authenticated endpoint boundaries.' },
    ],
  },
  {
    key: 'infrastructureReview',
    label: 'Infrastructure Review',
    icon: 'Server',
    tools: [
      { name: 'API Schema Analysis', command: `curl -s https://${target}/graphql?query={__schema{types{name}}}`, description: 'Mapping GraphQL and REST structures for data exposure risks.' },
      { name: 'Cloud Config Audit', command: `kubectl auth can-i --list --namespace=${target}`, description: 'Validating Kubernetes and Cloud service account permissions.' },
    ],
  },
  {
    key: 'liveHostDiscovery',
    label: 'Live Host Discovery',
    icon: 'Radar',
    tools: [
      { name: 'HTTP Probe', command: `httpx -l ${target}_subs.txt -silent -status-code`, description: 'Identifying live and responsive hosts across the target infrastructure.' },
      { name: 'Port Enumeration', command: `naabu -host ${target} -top-ports 1000`, description: 'Scanning for open network ports and exposed services.' },
    ],
  },
  {
    key: 'urlCollection',
    label: 'URL Collection',
    icon: 'Link',
    tools: [
      { name: 'Wayback Crawl', command: `waybackurls ${target} | sort -u`, description: 'Harvesting historical URLs from web archive records.' },
      { name: 'Parameter Mining', command: `paramspider -d ${target}`, description: 'Extracting URL parameters for input vector analysis.' },
    ],
  },
  {
    key: 'directoryBruteforcing',
    label: 'Directory Bruteforcing',
    icon: 'FolderSearch',
    tools: [
      { name: 'Path Discovery', command: `ffuf -u https://${target}/FUZZ -w wordlist.txt`, description: 'Enumerating hidden directories and sensitive file paths.' },
      { name: 'Backup Detection', command: `gobuster dir -u https://${target} -w backup-list.txt`, description: 'Locating exposed backup files and configuration artifacts.' },
    ],
  },
  {
    key: 'wordpressSecurity',
    label: 'WordPress Security',
    icon: 'FileCode',
    tools: [
      { name: 'CMS Audit', command: `wpscan --url https://${target} --enumerate vp,vt,u`, description: 'Comprehensive audit of WordPress installations and plugins.' },
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
      { name: 'Dangling DNS', command: `subjack -w ${target}_subs.txt -t 100 -ssl`, description: 'Detecting unclaimed DNS records vulnerable to takeover.' },
    ],
  },
  {
    key: 'gitDisclosure',
    label: 'Git Disclosure',
    icon: 'GitBranch',
    tools: [
      { name: 'Repository Exposure', command: `git-dumper https://${target}/.git/ output/`, description: 'Checking for exposed version control repositories.' },
    ],
  },
  {
    key: 'ssrfSection',
    label: 'SSRF Analysis',
    icon: 'Unplug',
    tools: [
      { name: 'Internal Reach', command: `curl "https://${target}/fetch?url=http://169.254.169.254/latest/meta-data/"`, description: 'Testing server-side request forgery vectors against internal services.' },
    ],
  },
  {
    key: 'redirectSection',
    label: 'Open Redirect',
    icon: 'ExternalLink',
    tools: [
      { name: 'Redirect Validation', command: `curl -Ls -o /dev/null -w "%{url_effective}" "https://${target}/redirect?url=https://evil.com"`, description: 'Verifying URL redirect sanitization controls.' },
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
    key: 'raceCondSection',
    label: 'Race Conditions',
    icon: 'Timer',
    tools: [
      { name: 'Concurrency Test', command: `turbo-intruder https://${target}/api/transfer`, description: 'Detecting time-of-check to time-of-use concurrency flaws.' },
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
    key: 'privescSection',
    label: 'Privilege Escalation',
    icon: 'TrendingUp',
    tools: [
      { name: 'Escalation Paths', command: `linpeas.sh`, description: 'Identifying potential privilege escalation vectors in system configurations.' },
    ],
  },
  {
    key: 'lateralSection',
    label: 'Lateral Movement',
    icon: 'Network',
    tools: [
      { name: 'Network Pivoting', command: `crackmapexec smb ${target}/24`, description: 'Assessing internal network traversal and pivoting opportunities.' },
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
      { name: 'Model Probing', command: `curl -X POST https://${target}/api/predict -d '{"input":"<adversarial>"}'`, description: 'Evaluating AI model endpoints for adversarial input vulnerabilities.' },
    ],
  },
];

export default createToolkitData;
