import json
import traceback
import hashlib
import yaml
import os
import subprocess
import tempfile
import requests
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from factory import create_app, db
from models import ReconFinding, Scan, Vulnerability
from scanner_core.scanner import Scanner
from scanner_core.scanner import Vulnerability as VulnerabilityDataClass

from integrations.nmap_scanner import run_nmap
from integrations.wafw00f_scanner import run_wafw00f
from integrations.dnsrecon_scanner import run_dnsrecon
from integrations.nuclei_scanner import run_nuclei
from integrations.service_auditor import audit_service_version
from integrations.sqlmap_scanner import run_sqlmap
from integrations.playwright_crawler import PlaywrightCrawler
from integrations.waf_bypass_scanner import run_waf_bypass
from integrations.whatweb_scanner import run_whatweb
from integrations.wappalyzer_scanner import run_wappalyzer
from utils.swagger_parser import discover_api_from_swagger
from utils.cvss_calc import parse_and_calculate_cvss
from utils.tree_builder import build_site_tree

try:
    with open('config/knowledge_base.yml', 'r', encoding='utf-8') as f:
        KNOWLEDGE_BASE = yaml.safe_load(f)
except Exception:
    KNOWLEDGE_BASE = {}


def get_kb_info(vuln_type):
    for key, value in KNOWLEDGE_BASE.items():
        if vuln_type.startswith(key) or key in vuln_type:
            return value
    return KNOWLEDGE_BASE.get('default', {})


def _generate_dedup_hash(vuln: VulnerabilityDataClass) -> str:
    GLOBAL_VULN_TYPES = ['Cryptographic Failure', 'Security Misconfiguration',
                         'Security Logging and Monitoring Failure', 'Outdated Service Component',
                         'Using Components with Known Vulnerabilities', 'Software and Data Integrity Failure',
                         'Sensitive Data Exposure', 'Cross-Site Request Forgery (CSRF)', 'CSRF']
    parsed = urlparse(vuln.url)
    domain = parsed.netloc
    path = parsed.path
    details_str = ""
    if isinstance(vuln.details, dict):
        if 'parameter' in vuln.details:
            details_str += f"|param:{vuln.details['parameter']}"
        elif 'library' in vuln.details:
            details_str += f"|lib:{vuln.details['library']}"
        elif 'cookie' in vuln.details:
            name = vuln.details['cookie'].split('=')[0] if '=' in vuln.details['cookie'] else vuln.details['cookie']
            details_str += f"|cookie:{name}"
        elif 'match' in vuln.details:
            details_str += f"|match:{vuln.details['match']}"
        elif 'leak_type' in vuln.details:
            details_str += f"|leak_type:{vuln.details['leak_type']}"
        elif 'form_action' in vuln.details:
            details_str += f"|action:{vuln.details['form_action']}"
    if any(g_type in vuln.type for g_type in GLOBAL_VULN_TYPES):
        unique_string = f"{vuln.type}|{vuln.subcategory}|{domain}{details_str}"
    else:
        unique_string = f"{vuln.type}|{vuln.subcategory}|{domain}|{path}{details_str}"
    return hashlib.md5(unique_string.encode('utf-8')).hexdigest()


def check_host_alive(url: str, cookies: str = None) -> bool:
    headers = {'User-Agent': 'Mozilla/5.0', 'ngrok-skip-browser-warning': 'true'}
    cookie_dict = {}
    if cookies:
        for item in cookies.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookie_dict[k] = v
    try:
        requests.get(url, headers=headers, cookies=cookie_dict, timeout=10, verify=False, allow_redirects=True)
        return True
    except requests.exceptions.RequestException:
        return False


def is_ip_address(host: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) is not None


def run_scan_task(scan_id: int):
    app = create_app()
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan: return

        print(f"Worker started for Scan ID: {scan_id}, Mode: {scan.scan_mode}", flush=True)

        if not check_host_alive(scan.target_url, scan.auth_cookies):
            print(f"[Scan ID: {scan_id}] ERROR: Host is unreachable. Aborting.", flush=True)
            scan.status = 'FAILED'
            scan.end_time = datetime.now(timezone.utc)
            db.session.commit()
            return

        scan.status = 'RUNNING'
        db.session.commit()

        seen_vuln_hashes = set()
        waf_detected = False
        is_windows = False

        try:
            scraped_urls = set()
            scraped_forms = []
            crawl_depth = 0 if scan.scan_mode == 'single' else 2

            # --- PHASE 0: CRAWLING ---
            if crawl_depth > 0:
                print(f"[Scan ID: {scan_id}] Running Scrapy Spider...", flush=True)
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
                    out_file = tmp_file.name
                cmd = ['scrapy', 'runspider', 'integrations/scrapy_spider.py', '-a', f'target={scan.target_url}', '-a',
                       f'depth_limit={crawl_depth}']
                if scan.auth_cookies: cmd.extend(['-a', f'auth_cookies={scan.auth_cookies}'])
                cmd.extend(['-o', out_file])
                subprocess.run(cmd, capture_output=True)
                if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                    with open(out_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for item in data:
                            if item.get('type') == 'url':
                                scraped_urls.add(item['url'])
                            elif item.get('type') == 'form':
                                scraped_forms.append(item)
                if os.path.exists(out_file): os.remove(out_file)
            else:
                scraped_urls.add(scan.target_url)

            print(f"[Scan ID: {scan_id}] Running Playwright Crawler...", flush=True)
            pw_crawler = PlaywrightCrawler(scan.target_url, scan.auth_cookies, scan.scan_mode)
            hidden_apis = pw_crawler.crawl()
            if hidden_apis:
                scraped_forms.extend(hidden_apis)
                for api in hidden_apis: scraped_urls.add(api['url'])

            swagger_forms = discover_api_from_swagger(scan.target_url, scan.auth_cookies)
            if swagger_forms:
                scraped_forms.extend(swagger_forms)
                for sf in swagger_forms: scraped_urls.add(sf['url'])

            scraped_urls.add(scan.target_url)
            site_tree = build_site_tree(list(scraped_urls))
            scan.site_tree = json.dumps(site_tree)
            scan.discovered_forms = json.dumps(scraped_forms)
            db.session.commit()

            # --- PHASE 1: RECONNAISSANCE ---
            parsed_url = urlparse(scan.target_url)
            domain = parsed_url.hostname

            waf_result = run_wafw00f(scan.target_url)
            if waf_result:
                waf_detected = True
                db.session.add(ReconFinding(scan_id=scan.id, tool='wafw00f', finding_type='WAF Detected',
                                            details=json.dumps(waf_result)))
                waf_bypass_results = run_waf_bypass(scan.target_url)
                for result in waf_bypass_results:
                    db.session.add(
                        ReconFinding(scan_id=scan.id, tool=result['tool'], finding_type=result['finding_type'],
                                     details=json.dumps(result['details'])))
                db.session.commit()

            if domain and not is_ip_address(domain):
                dns_results = run_dnsrecon(domain)
                for record in dns_results:
                    db.session.add(ReconFinding(scan_id=scan.id, tool='dnsrecon',
                                                finding_type=f"DNS Record ({record.get('type', 'Unknown')})",
                                                details=json.dumps(record)))
                db.session.commit()

            if domain:
                nmap_data = run_nmap(domain)
                for port_info in nmap_data.get('ports', []):
                    db.session.add(ReconFinding(scan_id=scan.id, tool='nmap', finding_type='Open Port',
                                                details=json.dumps(port_info)))
                    if 'windows' in json.dumps(port_info).lower(): is_windows = True
                    product, version = port_info.get('product'), port_info.get('version')
                    if product and version:
                        vulns = audit_service_version(product, version)
                        for v in vulns:
                            max_score = v.get('score', 0)
                            sev = 'Critical' if max_score >= 9.0 else 'High' if max_score >= 7.0 else 'Medium'
                            v_hash = _generate_dedup_hash(
                                VulnerabilityDataClass(type='Outdated Service Component', url=scan.target_url,
                                                       details=v, severity=sev))
                            if v_hash not in seen_vuln_hashes:
                                db.session.add(Vulnerability(scan_id=scan.id, type='Outdated Service Component',
                                                             subcategory=f"{product} {version}", url=scan.target_url,
                                                             severity=sev, cvss_score=max_score,
                                                             details=json.dumps(v, indent=2)))
                                seen_vuln_hashes.add(v_hash)
                db.session.commit()

            # --- PHASE 2: NUCLEI ---
            for n_vuln in run_nuclei(scan.target_url):
                v_hash = _generate_dedup_hash(
                    VulnerabilityDataClass(type=f"[Nuclei] {n_vuln['type']}", url=n_vuln['url'],
                                           severity=n_vuln['severity'], details=n_vuln['details']))
                if v_hash not in seen_vuln_hashes:
                    kb = get_kb_info(n_vuln['type'])
                    db.session.add(
                        Vulnerability(scan_id=scan.id, type=f"[Nuclei] {n_vuln['type']}", severity=n_vuln['severity'],
                                      url=n_vuln['url'], cvss_score=kb.get('cvss_score'),
                                      details=json.dumps(n_vuln['details'], indent=2)))
                    seen_vuln_hashes.add(v_hash)
            db.session.commit()

            # --- PHASE 3: SQLMAP ---
            for result in run_sqlmap(scan.target_url, scan.auth_cookies):
                db.session.add(Vulnerability(scan_id=scan.id, type="SQL Injection (Verified)", subcategory="Automated",
                                             url=scan.target_url, severity="Critical",
                                             details=json.dumps(result, indent=2)))
            db.session.commit()

            # --- PHASE 4: CORE SCANNER ---
            def save_vulnerability_callback(vuln: VulnerabilityDataClass):
                with app.app_context():
                    v_hash = _generate_dedup_hash(vuln)
                    if v_hash in seen_vuln_hashes: return

                    kb_info = get_kb_info(vuln.type)
                    cvss_vector = vuln.cvss_vector or kb_info.get('cvss_vector')
                    cvss_score, severity = vuln.cvss_score, vuln.severity
                    if cvss_vector:
                        calculated_score, calc_severity = parse_and_calculate_cvss(cvss_vector)
                        if calculated_score is not None: cvss_score, severity = calculated_score, calc_severity

                    db.session.add(
                        Vulnerability(scan_id=scan.id, type=vuln.type, subcategory=getattr(vuln, 'subcategory', None),
                                      url=vuln.url, severity=severity, cvss_score=cvss_score, cvss_vector=cvss_vector,
                                      cwe=kb_info.get('cwe', 'N/A'),
                                      details=json.dumps(vuln.details, indent=2, ensure_ascii=False)))
                    db.session.commit()
                    seen_vuln_hashes.add(v_hash)

            scanner_instance = Scanner(url=scan.target_url, cookies=scan.auth_cookies, depth=crawl_depth,
                                       pre_crawled_urls=scraped_urls, discovered_forms=scraped_forms,
                                       waf_detected=waf_detected, is_windows=is_windows)
            scanner_instance.scan(vulnerability_callback=save_vulnerability_callback)

            # --- PHASE 5: AI SUMMARY ---
            scan = db.session.get(Scan, scan_id)
            if bool(scan.recon_findings) or bool(scan.vulnerabilities):
                vuln_summary = [{'type': v.type, 'severity': v.severity} for v in scan.vulnerabilities]
                analysis = generate_overall_analysis(scan.target_url, vuln_summary)
                if analysis:
                    scan.ai_analysis = json.dumps(analysis, indent=2)
                    db.session.commit()

            scan.status = 'COMPLETED'
            print(f"Scan ID: {scan_id} completed successfully.", flush=True)

        except Exception as e:
            traceback.print_exc()
            db.session.rollback()
            scan = db.session.get(Scan, scan_id)
            if scan: scan.status = 'FAILED'
        finally:
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.end_time = datetime.now(timezone.utc)
                db.session.commit()
            print(f"Worker finished for Scan ID: {scan_id}", flush=True)