import requests
import ssl
import socket
import re
import networkx as nx
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Tag
from collections import deque
from datetime import datetime
from typing import List, Dict, Set, Tuple, Any

Finding = Tuple[str, str]

class Scanner:

    def __init__(self, start_url: str, standards: List[str], mode: str, max_pages: int = 20, max_depth: int = 3):
        if not start_url.startswith(('http://', 'https://')):
            self.start_url: str = 'https://' + start_url
        else:
            self.start_url: str = start_url
        
        self.standards: List[str] = standards
        self.mode: str = mode
        
        if self.mode == 'Aggressive/Full':
            self.max_pages: int = 50
            self.max_depth: int = 5
        else:
            self.max_pages: int = 10
            self.max_depth: int = 2

        self.results: Dict[str, Dict[str, Any]] = {}
        self.site_graph: nx.DiGraph = nx.DiGraph()
        self.domain: str = urlparse(self.start_url).netloc
        
        self.session: requests.Session = requests.Session()
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.print = print

    def run_scan(self) -> Dict[str, Any]:
        queue: deque = deque([(self.start_url, 0)])
        visited: Set[str] = {self.start_url}
        is_first_page = True

        while queue and len(self.results) < self.max_pages:
            current_url, depth = queue.popleft()
            self.print(f"Scanning: {current_url} (Depth: {depth})")
            self.site_graph.add_node(current_url)

            page_results = {
                "https": {"findings": []}, "forms": {"findings": []}
            }
            page_results['https']['findings'].extend(self.check_ssl_certificate(current_url))

            try:
                response = self.session.get(current_url, timeout=10, verify=False, allow_redirects=True)
                final_url = response.url.rstrip('/')

                if not urlparse(final_url).netloc.endswith(self.domain):
                    self.print(f"Skipping external link after redirect: {final_url}")
                    if final_url not in self.site_graph:
                        self.site_graph.add_node(final_url)
                    self.site_graph.add_edge(current_url, final_url)
                    continue

                if final_url != current_url and final_url in visited:
                    self.site_graph.add_edge(current_url, final_url)
                    continue

                if final_url != current_url:
                    visited.add(final_url)
                    if current_url in self.results:
                        self.results[final_url] = self.results.pop(current_url)
                    else:
                        self.results[final_url] = {"https": {"findings": []}, "forms": {"findings": []}}
                    current_url = final_url

                soup = BeautifulSoup(response.content, 'html.parser')

                if is_first_page:
                    domain_findings = {
                        "headers": self.check_security_headers(response),
                        "cookies": self.check_cookies(response),
                        "tech": self.check_tech_stack(soup)
                    }
                    if 'GDPR' in self.standards:
                        domain_findings["privacy"] = self.check_privacy_policy_link(soup, response.url)
                    if 'PCI-DSS' in self.standards:
                        domain_findings["pci"] = self.check_pci_dss(response, soup)
                    if 'ISO 27001' in self.standards:
                        domain_findings["iso"] = self.check_iso_27001(response)

                    self.results['domain_findings'] = domain_findings
                    is_first_page = False

                page_form_findings = self.check_forms(soup, response.url)
                if current_url in self.results and "forms" in self.results[current_url]:
                    self.results[current_url]["forms"]["findings"].extend(page_form_findings)

                if depth < self.max_depth:
                    links = self._find_links(soup, current_url)
                    for link in sorted(links):
                        if link not in visited and len(visited) < self.max_pages:
                            visited.add(link)
                            self.site_graph.add_edge(current_url, link)
                            queue.append((link, depth + 1))

            except requests.RequestException as e:
                self.print(f"Error connecting to {current_url}: {e}")
                if current_url not in self.results:
                    self.results[current_url] = {}
                if 'https' not in self.results[current_url]:
                    self.results[current_url]['https'] = {'findings': []}
                self.results[current_url]['https']['findings'].append(('critical', f'Could not connect to the page: {e}'))

        self.print("Scan finished.")
        return {"pages": self.results, "graph": self.site_graph, "start_url": self.start_url, "standards": self.standards, "mode": self.mode}

    def _scan_page_content(self, response: requests.Response, soup: BeautifulSoup) -> Dict[str, List[Finding]]:
        findings = {
            "headers": self.check_security_headers(response),
            "cookies": self.check_cookies(response),
            "tech": self.check_tech_stack(soup),
            "forms": self.check_forms(soup, response.url)
        }
        if not response.url.startswith('https://'):
            findings["headers"].append(('high', 'Page does not automatically redirect to HTTPS.'))
        else:
            findings["headers"].append(('pass', 'Page correctly uses HTTPS.'))
        return findings
        
    def _find_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        links: Set[str] = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            url = urljoin(base_url, href)
            parsed_url = urlparse(url)
            clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}".rstrip('/')
            
            if urlparse(clean_url).netloc.endswith(self.domain):
                links.add(clean_url)
        return links

    def check_ssl_certificate(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        hostname = urlparse(url).hostname
        if not hostname:
            return findings

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if expiry_date < datetime.now():
                        findings.append(('high', f"The SSL certificate for '{hostname}' expired on {expiry_date.date()}."))
                    else:
                        findings.append(('pass', f"The SSL certificate for '{hostname}' is valid until {expiry_date.date()}."))
        except ssl.SSLCertVerificationError:
            findings.append(('high', f"The SSL certificate for '{hostname}' is invalid or expired (verification error)."))
        except (socket.gaierror, socket.timeout):
            findings.append(('high', f"Could not connect to server '{hostname}' to verify the certificate."))
        except Exception as e:
            findings.append(('high', f"Could not verify SSL certificate: {e}"))
        
        return findings

    def check_security_headers(self, response: requests.Response) -> List[Finding]:
        findings: List[Finding] = []
        headers_to_check = {
            'Strict-Transport-Security': 'high', 'Content-Security-Policy': 'medium',
            'X-Content-Type-Options': 'low', 'X-Frame-Options': 'medium',
            'Referrer-Policy': 'low'
        }
        for header, severity in headers_to_check.items():
            if header not in response.headers:
                findings.append((severity, f"Missing security header: '{header}'."))
            else:
                findings.append(('pass', f"Found header: '{header}'."))
        return findings

    def check_cookies(self, response: requests.Response) -> List[Finding]:
        findings: List[Finding] = []
        
        if not response.cookies:
            return [('pass', 'The page does not set cookies in this response.')]
            
        for cookie in response.cookies:
            name = f"Cookie '{cookie.name}'"
            if not cookie.secure:
                findings.append(('high', f"{name} does not have the 'Secure' flag."))
            else:
                findings.append(('pass', f"{name} has the 'Secure' flag."))

            set_cookie_header = response.headers.get('Set-Cookie', '')
            if 'httponly' not in set_cookie_header.lower():
                 findings.append(('medium', f"{name} probably does not have the 'HttpOnly' flag."))
            else:
                findings.append(('pass', f"{name} has the 'HttpOnly' flag."))

            if 'samesite' not in set_cookie_header.lower():
                 findings.append(('medium', f"{name} probably does not have the 'SameSite' attribute."))
            else:
                findings.append(('pass', f"{name} has the 'SameSite' attribute."))
        return findings

    def check_tech_stack(self, soup: BeautifulSoup) -> List[Finding]:
        findings: List[Finding] = []
        
        generator_meta = soup.find('meta', {'name': 'generator'})
        if generator_meta and 'WordPress' in generator_meta.get('content', ''):
            version = generator_meta.get('content').split(' ')[-1]
            findings.append(('low', f"Detected WordPress version {version}. Check for updates regularly."))

        jquery_script = soup.find('script', src=lambda s: s and 'jquery' in s.lower())
        if jquery_script:
            src = jquery_script.get('src', '')
            match = re.search(r'jquery-([0-9]+\.[0-9]+\.[0-9]+)', src)
            if match:
                version = match.group(1)
                findings.append(('low', f"Detected jQuery version {version}. Verify if it has any known vulnerabilities (CVEs)."))
            else:
                findings.append(('pass', "Detected jQuery library (could not determine specific version)."))
                
        return findings
    
    def check_forms(self, soup: BeautifulSoup, base_url: str) -> List[Finding]:
        findings: List[Finding] = []
        forms = soup.find_all('form')
        if not forms:
            return [('pass', 'No forms found on the page.')]
            
        for i, form in enumerate(forms):
            form_id = f"Form #{i+1}"
            
            action = form.get('action', '')
            action_url = urljoin(base_url, action)
            if not action_url.startswith('https://'):
                findings.append(('high', f"{form_id} submits data to an insecure address."))
            
            has_csrf_token = form.find('input', {'name': re.compile(r'csrf_token|nonce', re.IGNORECASE)})
            if not has_csrf_token:
                findings.append(('medium', f"{form_id} probably does not have an anti-CSRF token."))

        return findings

    def check_privacy_policy_link(self, soup: BeautifulSoup, base_url: str) -> List[Finding]:
        findings: List[Finding] = []
        
        privacy_link_texts = ['privacy policy']
        
        found_link = soup.find('a', string=re.compile(r'|'.join(privacy_link_texts), re.IGNORECASE))
        
        if found_link and found_link.get('href'):
            findings.append(('pass', f"Found a link to the privacy policy: '{found_link.text.strip()}'"))
        else:
            findings.append(('medium', 'No direct link to the privacy policy was found on the main page. This is recommended under GDPR.'))
            
        return findings

    def check_pci_dss(self, response: requests.Response, soup: BeautifulSoup) -> List[Finding]:
        findings: List[Finding] = []
        forms = soup.find_all('form')
        
        password_fields_found = False
        for form in forms:
            password_inputs = form.find_all('input', {'type': 'password'})
            for password_input in password_inputs:
                password_fields_found = True
                if password_input.get('autocomplete', 'on').lower() != 'off':
                    findings.append(('medium', "A password field was found without 'autocomplete=\"off\"', which is recommended by PCI-DSS."))
        
        if not password_fields_found:
            findings.append(('pass', 'No password fields were found on the page.'))
        elif not findings:
            findings.append(('pass', 'All found password fields have autocomplete disabled.'))

        return findings

    def check_iso_27001(self, response: requests.Response) -> List[Finding]:
        findings: List[Finding] = []
        security_txt_url = urljoin(response.url, '/.well-known/security.txt')
        try:
            res = self.session.get(security_txt_url, timeout=5)
            if res.status_code == 200:
                findings.append(('pass', 'Found a security.txt file, which is good practice under ISO 27001.'))
            else:
                findings.append(('low', 'Missing security.txt file. Consider adding one to facilitate contact regarding security matters.'))
        except requests.RequestException:
            findings.append(('low', 'Could not check for the presence of a security.txt file.'))
        return findings 