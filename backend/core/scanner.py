import logging
import time
import requests
import ssl
import socket
import re
import networkx as nx
import uuid
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Tag
from collections import deque
from datetime import datetime
from typing import List, Dict, Set, Tuple, Any, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..core.exceptions import ScannerConfigError, ScannerError, NetworkError
from ..security.validators import URLValidator, ScanConfigValidator
from ..security.rate_limiter import DomainRateLimiter
from ..utils.monitoring import get_metrics_collector
from ..utils.logging_config import get_logger

Finding = Tuple[str, str]

logger = get_logger("scanner")

class Scanner:

    def __init__(
        self,
        start_url: str,
        standards: List[str],
        mode: str,
        *,
        max_pages: int | None = None,
        max_depth: int | None = None,
        timeout: int = 10,
        verify_ssl: bool = True,
        user_agent: str | None = None,
        logger_instance: logging.Logger | None = None,
        enable_rate_limiting: bool = True,
        enable_metrics: bool = True,
    ):
        self.scan_id = str(uuid.uuid4())
        
        self.start_url = URLValidator.validate(start_url, allow_localhost=True)
        ScanConfigValidator.validate_mode(mode)
        self.standards = ScanConfigValidator.validate_standards(standards)
        
        max_pages = ScanConfigValidator.validate_max_pages(max_pages)
        max_depth = ScanConfigValidator.validate_max_depth(max_depth)
        timeout = ScanConfigValidator.validate_timeout(timeout)

        self.mode: str = mode

        if self.mode == "Aggressive/Full":
            default_max_pages = 50
            default_max_depth = 5
        else:
            default_max_pages = 10
            default_max_depth = 2

        self.max_pages: int = max_pages if max_pages is not None else default_max_pages
        self.max_depth: int = max_depth if max_depth is not None else default_max_depth

        self.timeout: int = timeout
        self.verify_ssl: bool = verify_ssl

        self.results: Dict[str, Dict[str, Any]] = {}
        self.site_graph: nx.DiGraph = nx.DiGraph()
        self.domain: str = urlparse(self.start_url).netloc

        self.session: requests.Session = self._create_session(user_agent)
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        self.logger: logging.Logger = logger_instance or logger
        self.print = print
        
        self.rate_limiter: Optional[DomainRateLimiter] = None
        if enable_rate_limiting:
            self.rate_limiter = DomainRateLimiter(requests_per_second=5.0)
        
        self.metrics = get_metrics_collector() if enable_metrics else None
        self.request_count = 0
        self.error_count = 0

    def _create_session(self, user_agent: Optional[str]) -> requests.Session:
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/91.0.4472.124 Safari/537.36"
            ),
        })
        
        return session
    
    def _emit_log(self, level: int, message: str) -> None:
        self.logger.log(level, message)
        try:
            if self.print is not None:
                self.print(message)
        except Exception:
            self.logger.debug("Log callback raised an exception", exc_info=True)

    def run_scan(self) -> Dict[str, Any]:
        if self.metrics:
            self.metrics.start_scan(self.scan_id, self.start_url)
        
        self._emit_log(logging.INFO, f"Starting scan {self.scan_id} for {self.start_url}")
        
        try:
            return self._execute_scan()
        except Exception as e:
            self.error_count += 1
            self._emit_log(logging.ERROR, f"Scan failed with error: {e}")
            if self.metrics:
                self.metrics.end_scan(self.scan_id, status="failed")
                self.metrics.record_error(type(e).__name__)
            raise ScannerError(f"Scan execution failed: {e}", details={"scan_id": self.scan_id})
        finally:
            self.session.close()
    
    def _execute_scan(self) -> Dict[str, Any]:
        queue: deque = deque([(self.start_url, 0)])
        visited: Set[str] = {self.start_url}
        is_first_page = True

        while queue and len(self.results) < self.max_pages:
            current_url, depth = queue.popleft()
            self._emit_log(logging.INFO, f"Scanning: {current_url} (Depth: {depth})")
            self.site_graph.add_node(current_url)

            if current_url not in self.results:
                self.results[current_url] = {"https": {"findings": []}, "forms": {"findings": []}}

            self.results[current_url]["https"]["findings"].extend(self.check_ssl_certificate(current_url))

            request_started = time.time()

            try:
                if self.rate_limiter:
                    self.rate_limiter.acquire(self.domain, blocking=True, timeout=30)
                
                response = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                )
                elapsed_ms = int((time.time() - request_started) * 1000)
                self.request_count += 1
                
                if self.metrics:
                    self.metrics.record_request(time.time() - request_started)
                    self.metrics.update_scan_metrics(
                        self.scan_id,
                        pages_scanned=len(self.results),
                        requests_made=self.request_count
                    )
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

                if current_url not in self.results:
                    self.results[current_url] = {"https": {"findings": []}, "forms": {"findings": []}}

                page_entry = self.results[current_url]
                meta = page_entry.setdefault("meta", {})
                meta["status_code"] = response.status_code
                meta["response_time_ms"] = elapsed_ms
                meta["content_type"] = response.headers.get("Content-Type")
                meta["error"] = False
                meta["error_message"] = None

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
                if current_url not in self.results:
                    self.results[current_url] = {"https": {"findings": []}, "forms": {"findings": []}}

                if "forms" in self.results[current_url]:
                    self.results[current_url]["forms"]["findings"].extend(page_form_findings)

                if depth < self.max_depth:
                    links = self._find_links(soup, current_url)
                    for link in sorted(links):
                        if link not in visited and len(visited) < self.max_pages:
                            visited.add(link)
                            self.site_graph.add_edge(current_url, link)
                            queue.append((link, depth + 1))

            except requests.RequestException as e:
                self.error_count += 1
                self._emit_log(logging.WARNING, f"Error connecting to {current_url}: {e}")
                
                if self.metrics:
                    self.metrics.record_error("RequestException")
                    self.metrics.update_scan_metrics(
                        self.scan_id,
                        errors_count=self.error_count
                    )
                
                if current_url not in self.results:
                    self.results[current_url] = {}
                if 'https' not in self.results[current_url]:
                    self.results[current_url]['https'] = {'findings': []}
                self.results[current_url]['https']['findings'].append(('critical', f'Could not connect to the page: {e}'))

                page_entry = self.results[current_url]
                meta = page_entry.setdefault("meta", {})
                meta["status_code"] = None
                meta["response_time_ms"] = int((time.time() - request_started) * 1000)
                meta["content_type"] = None
                meta["error"] = True
                meta["error_message"] = str(e)
        self._emit_log(logging.INFO, "Scan finished.")
        
        if self.metrics:
            self.metrics.end_scan(self.scan_id, status="completed")
        
        return {
            "schema_version": "1.0",
            "scan_id": self.scan_id,
            "pages": self.results,
            "graph": self.site_graph,
            "start_url": self.start_url,
            "standards": self.standards,
            "mode": self.mode,
            "metrics": {
                "total_requests": self.request_count,
                "total_errors": self.error_count,
                "pages_scanned": len([k for k in self.results.keys() if k != "domain_findings"]),
            },
        }

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
        
        set_cookie_headers = []
        if hasattr(response, 'raw') and hasattr(response.raw, '_original_response'):
            try:
                set_cookie_headers = response.raw._original_response.msg.get_all('Set-Cookie') or []
            except (AttributeError, TypeError):
                pass
        
        if not set_cookie_headers:
            single_header = response.headers.get('Set-Cookie', '')
            if single_header:
                set_cookie_headers = [single_header]
        
        for cookie in response.cookies:
            name = f"Cookie '{cookie.name}'"
            
            if not cookie.secure:
                findings.append(('high', f"{name} does not have the 'Secure' flag."))
            else:
                findings.append(('pass', f"{name} has the 'Secure' flag."))

            cookie_header = ''
            for header in set_cookie_headers:
                if header and cookie.name in header:
                    cookie_header = header.lower()
                    break
            
            if cookie_header:
                if 'httponly' not in cookie_header:
                    findings.append(('medium', f"{name} does not have the 'HttpOnly' flag."))
                else:
                    findings.append(('pass', f"{name} has the 'HttpOnly' flag."))

                if 'samesite' not in cookie_header:
                    findings.append(('medium', f"{name} does not have the 'SameSite' attribute."))
                else:
                    findings.append(('pass', f"{name} has the 'SameSite' attribute."))
            else:
                findings.append(('low', f"{name} attributes could not be fully verified."))
        
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
            
            csrf_patterns = [
                r'csrf',
                r'xsrf', 
                r'_token',
                r'authenticity_token',
                r'nonce',
                r'anti-forgery'
            ]
            
            has_csrf_token = False
            for pattern in csrf_patterns:
                if form.find('input', {'name': re.compile(pattern, re.IGNORECASE)}):
                    has_csrf_token = True
                    break
                if form.find('input', {'type': 'hidden', 'value': re.compile(r'^[a-f0-9]{32,}$', re.IGNORECASE)}):
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                sensitive_inputs = form.find_all('input', {'type': re.compile(r'password|email', re.IGNORECASE)})
                if sensitive_inputs:
                    findings.append(('medium', f"{form_id} with sensitive fields does not appear to have CSRF protection."))
                else:
                    findings.append(('low', f"{form_id} does not appear to have CSRF protection."))

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