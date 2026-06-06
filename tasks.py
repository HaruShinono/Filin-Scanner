# tasks.py
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
from integrations.service_auditor import audit_service_version, get_vulners_api
from integrations.waf_bypass_scanner import run_waf_bypass
from integrations.whatweb_scanner import run_whatweb
from integrations.wappalyzer_scanner import run_wappalyzer
from integrations.retirejs_scanner import run_retirejs
from utils.swagger_parser import discover_api_from_swagger
from utils.cvss_calc import calculate_vulnerability_cvss
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
                         'Using Components with Known Vulnerabilities', 'Vulnerable and Outdated Service Component',
                         'Software and Data Integrity Failure', 'Sensitive Data Exposure',
                         'Cross-Site Request Forgery (CSRF)', 'CSRF']
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
            print(f"[Scan ID: {scan_id}] ERROR: Host is unreachable or down. Aborting scan.", flush=True)
            scan.status = 'FAILED'
            scan.end_time = datetime.now(timezone.utc)
            db.session.commit()
            return

        scan.status = 'RUNNING'
        db.session.commit()

        seen_vuln_hashes = set()
        waf_detected = False
        is_windows = False
        discovered_components = []

        # =====================================================================
        # ĐỊNH NGHĨA SỚM CALLBACK LƯU LỖ HỔNG ĐỂ TRÁNH LỖI UNBOUNDLOCALERROR
        # =====================================================================
        def save_vulnerability_callback(vuln: VulnerabilityDataClass):
            v_hash = _generate_dedup_hash(vuln)
            if v_hash in seen_vuln_hashes: return

            kb_info = get_kb_info(vuln.type)

            # --- KIỂM TRA NẾU LÀ LỖ HỔNG COMPONENT THÌ LẤY THẲNG ĐIỂM TỪ VULN ĐÃ ĐƯỢC AUDIT ---
            if "components with known vulnerabilities" in vuln.type.lower() or "outdated" in vuln.type.lower() or "vulnerable and outdated" in vuln.type.lower():
                cvss_score = vuln.cvss_score if vuln.cvss_score is not None else 0.0
                cvss_vector = vuln.cvss_vector if (vuln.cvss_vector and vuln.cvss_vector != 'UNKNOWN') else None

                from utils.cvss_calc import get_severity
                severity = get_severity(cvss_score)
            else:
                # --- TÍNH ĐIỂM DYNAMIC THEO CVSS v3.1 LOGIC CHO CÁC LỖ HỔNG KHÁC ---
                has_auth = bool(scan.auth_cookies)
                cvss_score, cvss_vector, severity = calculate_vulnerability_cvss(
                    vuln.type,
                    getattr(vuln, 'subcategory', None),
                    has_auth
                )

            db.session.add(
                Vulnerability(scan_id=scan.id, type=vuln.type, subcategory=getattr(vuln, 'subcategory', None),
                              url=vuln.url, severity=severity, cvss_score=cvss_score, cvss_vector=cvss_vector,
                              cwe=kb_info.get('cwe', 'N/A'),
                              details=json.dumps(vuln.details, indent=2, ensure_ascii=False)))
            db.session.commit()
            seen_vuln_hashes.add(v_hash)

        # =====================================================================

        try:
            scraped_urls = set()
            scraped_forms = []
            crawl_depth = 0 if scan.scan_mode == 'single' else 2

            if crawl_depth > 0:
                print(f"[Scan ID: {scan_id}] Running Scrapy Spider (Depth: {crawl_depth})...", flush=True)
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

            print(f"[Scan ID: {scan_id}] Running Playwright Engine (Deep API Interception)...", flush=True)
            pw_crawler = PlaywrightCrawler(scan.target_url, scan.auth_cookies, scan.scan_mode)
            hidden_apis, mutated_urls = pw_crawler.crawl()

            if hidden_apis:
                scraped_forms.extend(hidden_apis)
                for api in hidden_apis:
                    scraped_urls.add(api['url'])

            if mutated_urls:
                for m_url in mutated_urls:
                    scraped_urls.add(m_url)

            swagger_forms = discover_api_from_swagger(scan.target_url, scan.auth_cookies)
            if swagger_forms:
                scraped_forms.extend(swagger_forms)
                print(f"  [API Discovery] Auto-generated {len(swagger_forms)} forms from OpenAPI spec.", flush=True)
                for sf in swagger_forms:
                    scraped_urls.add(sf['url'])

            scraped_urls.add(scan.target_url)
            site_tree = build_site_tree(list(scraped_urls))
            scan.site_tree = json.dumps(site_tree)
            scan.discovered_forms = json.dumps(scraped_forms)
            db.session.commit()
            print(f"  [Discovery Summary] Total URLs: {len(scraped_urls)} | Total Forms/APIs: {len(scraped_forms)}",
                  flush=True)

            print(f"[Scan ID: {scan_id}] Starting reconnaissance phase...", flush=True)
            parsed_url = urlparse(scan.target_url)
            domain = parsed_url.hostname

            waf_result = run_wafw00f(scan.target_url)
            if waf_result:
                waf_detected = True
                db.session.add(ReconFinding(scan_id=scan.id, tool='wafw00f', finding_type='WAF Detected',
                                            details=json.dumps(waf_result)))
                db.session.commit()
                print(f"  [Recon] WAF Detected: {waf_result.get('firewall', 'Unknown')}. Enabling evasive measures.",
                      flush=True)

                waf_bypass_results = run_waf_bypass(scan.target_url)
                for result in waf_bypass_results:
                    db.session.add(
                        ReconFinding(scan_id=scan.id, tool=result['tool'], finding_type=result['finding_type'],
                                     details=json.dumps(result['details'])))
                db.session.commit()

            whatweb_result = run_whatweb(scan.target_url)
            if whatweb_result:
                db.session.add(
                    ReconFinding(scan_id=scan.id, tool='whatweb', finding_type='Technology Fingerprint (WhatWeb)',
                                 details=json.dumps(whatweb_result)))
                db.session.commit()

                ww_str = json.dumps(whatweb_result).lower()
                if 'windows' in ww_str or 'iis' in ww_str or 'microsoft' in ww_str:
                    is_windows = True
                    print("  [Recon] Target OS detected as Windows via WhatWeb.", flush=True)

            wapp_result = run_wappalyzer(scan.target_url)
            if wapp_result:
                db.session.add(
                    ReconFinding(scan_id=scan.id, tool='wappalyzer', finding_type='Technology Fingerprint (Wappalyzer)',
                                 details=json.dumps(wapp_result)))
                db.session.commit()

                # Bóc tách Tên & Phiên bản từ Wappalyzer đưa vào danh sách chờ Audit
                for comp_name, comp_data in wapp_result.items():
                    versions = comp_data.get('versions', [])
                    for v in versions:
                        if v:
                            discovered_components.append({
                                'name': comp_name,
                                'version': v,
                                'source': 'Wappalyzer',
                                'url': scan.target_url
                            })

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

                    nmap_str = json.dumps(port_info).lower()
                    if 'windows' in nmap_str or 'microsoft' in nmap_str:
                        is_windows = True
                        print("  [Recon] Target OS detected as Windows via Nmap.", flush=True)

                    product, version = port_info.get('product'), port_info.get('version')
                    if product and version:
                        discovered_components.append({
                            'name': product,
                            'version': version,
                            'source': f"Nmap (Port {port_info.get('port')})",
                            'url': f"{scan.target_url}:{port_info.get('port')}"
                        })

                # Chuyển đổi Nmap NSE Vulnerabilities thành lỗ hổng ứng dụng chính thức
                for vuln_info in nmap_data.get('vulnerabilities', []):
                    script_id = vuln_info.get('script_id', 'NSE Script')
                    output_text = vuln_info.get('output', '')

                    cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", output_text, re.IGNORECASE)
                    max_score = 7.5
                    max_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

                    cve_list_text = f"CPE/Service: Nmap NSE Script ({script_id})\n"
                    cve_list_text += "-" * 70 + "\n"
                    cve_list_text += f"Port/Protocol: {vuln_info.get('port')}/{vuln_info.get('protocol')}\n"
                    cve_list_text += f"Nmap Script Output:\n{output_text}\n"

                    if cve_matches:
                        try:
                            unique_cves = list(set(cve_matches))
                            v_api = get_vulners_api()
                            for cve_id in unique_cves[:2]:
                                query_res = v_api.search(cve_id, limit=1)
                                if query_res:
                                    res = query_res[0]
                                    cvss_data = res.get('cvss3', res.get('cvss', {}))
                                    score = float(cvss_data.get('score', cvss_data.get('value', 7.5)))
                                    vector = cvss_data.get('vector', max_vector)
                                    if score > max_score:
                                        max_score = score
                                        max_vector = vector
                        except Exception as e:
                            print(f"Error fetching Nmap CVE detail from Vulners: {e}")

                    temp_vuln = VulnerabilityDataClass(
                        type='Vulnerable and Outdated Service Component',
                        subcategory=f"NSE: {script_id}",
                        url=f"{scan.target_url} (Port {vuln_info.get('port')})",
                        severity='',
                        cvss_score=max_score,
                        cvss_vector=max_vector,
                        details={
                            'Detected Via': 'Nmap Vulnerability Detection Script (NSE)',
                            'Vulnerability Details': cve_list_text
                        }
                    )
                    save_vulnerability_callback(temp_vuln)
                db.session.commit()
            print(f"[Scan ID: {scan_id}] Reconnaissance phase finished.", flush=True)

            print(f"[Scan ID: {scan_id}] Running Retire.js (Client-Side Component Analysis)...", flush=True)
            js_urls = [url for url in scraped_urls if url.lower().split('?')[0].endswith('.js')]
            if js_urls:
                retire_results = run_retirejs(js_urls, scan.auth_cookies)
                for r_vuln in retire_results:
                    cve_list_text = f"CPE/Component: {r_vuln['component']} ({r_vuln['version']})\n"
                    cve_list_text += "-" * 70 + "\n"

                    max_score = 0.0
                    for v in r_vuln['vulnerabilities']:
                        identifiers = v.get('identifiers', {})
                        cve = identifiers.get('CVE', [''])[0] if identifiers.get('CVE') else 'N/A'
                        summary = identifiers.get('summary', 'No summary provided')
                        sev = v.get('severity', 'low').lower()

                        score = 0.0
                        if sev == 'critical':
                            score = 9.8
                        elif sev == 'high':
                            score = 7.5
                        elif sev == 'medium':
                            score = 5.5
                        elif sev == 'low':
                            score = 3.0

                        max_score = max(max_score, score)
                        cve_list_text += f"{cve:<18} {score:<5} {summary[:60]}...\n"

                    temp_vuln = VulnerabilityDataClass(
                        type='Vulnerable and Outdated Service Component',
                        subcategory=f"{r_vuln['component'].title()} {r_vuln['version']} (JS)",
                        url=r_vuln['url'],
                        severity='',
                        cvss_score=max_score,
                        cvss_vector=None,
                        details={
                            'Detected Via': 'Retire.js',
                            'Vulnerability List': cve_list_text
                        }
                    )
                    save_vulnerability_callback(temp_vuln)
            else:
                print("  [Retire.js] No JavaScript files found to analyze.", flush=True)

            # =====================================================================
            # HỢP NHẤT AUDIT OWASP A06: VULNERABLE COMPONENTS (QUA VULNERS)
            # =====================================================================
            if discovered_components:
                print(
                    f"[Scan ID: {scan_id}] Auditing {len(discovered_components)} discovered components via Vulners API...",
                    flush=True)
                audited_keys = set()

                for comp in discovered_components:
                    comp_key = f"{comp['name'].lower()}:{comp['version']}"
                    if comp_key in audited_keys:
                        continue
                    audited_keys.add(comp_key)

                    vulns = audit_service_version(comp['name'], comp['version'])
                    if vulns:
                        max_vuln = max(vulns, key=lambda x: x.get('score', 0.0))
                        max_score = max_vuln.get('score', 0.0)
                        max_vector = max_vuln.get('vector', 'UNKNOWN')

                        sorted_vulns = sorted(vulns, key=lambda x: x.get('score', 0.0), reverse=True)
                        cve_list_text = f"CPE/Component: {comp['name']} ({comp['version']})\n"
                        cve_list_text += "-" * 70 + "\n"
                        for v in sorted_vulns:
                            cve_list_text += f"{v.get('id'):<18} {v.get('score'):<5} {v.get('href')}\n"

                        temp_vuln = VulnerabilityDataClass(
                            type='Vulnerable and Outdated Service Component',
                            subcategory=f"{comp['name'].title()} {comp['version']}",
                            url=comp['url'],
                            severity='',
                            cvss_score=max_score,
                            cvss_vector=max_vector,
                            details={
                                'Detected Via': comp['source'],
                                'Vulnerability List': cve_list_text
                            }
                        )
                        save_vulnerability_callback(temp_vuln)

            print(f"[Scan ID: {scan_id}] Starting Core Python Scanner...", flush=True)
            print(f"  [Core Scanner] Ready to test: {len(scraped_urls)} URLs and {len(scraped_forms)} Forms...",
                  flush=True)

            scanner_instance = Scanner(
                url=scan.target_url, cookies=scan.auth_cookies, depth=crawl_depth,
                pre_crawled_urls=scraped_urls, discovered_forms=scraped_forms,
                waf_detected=waf_detected, is_windows=is_windows
            )
            scanner_instance.scan(vulnerability_callback=save_vulnerability_callback)

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