import json
import traceback
import hashlib
import yaml
import os
import subprocess
import tempfile
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
from integrations.ai_remediator import generate_overall_analysis
from utils.cvss_calc import parse_and_calculate_cvss
from utils.tree_builder import build_site_tree

try:
    with open('config/knowledge_base.yml', 'r', encoding='utf-8') as f:
        KNOWLEDGE_BASE = yaml.safe_load(f)
except Exception as e:
    print(f"Failed to load KB: {e}")
    KNOWLEDGE_BASE = {}


def get_kb_info(vuln_type):
    for key, value in KNOWLEDGE_BASE.items():
        if vuln_type.startswith(key) or key in vuln_type:
            return value
    return KNOWLEDGE_BASE.get('default', {})


def _generate_dedup_hash(vuln: VulnerabilityDataClass) -> str:
    GLOBAL_VULN_TYPES = [
        'Cryptographic Failure',
        'Security Misconfiguration',
        'Security Logging and Monitoring Failure',
        'Outdated Service Component',
        'Using Components with Known Vulnerabilities',
        'Software and Data Integrity Failure',
        'Sensitive Data Exposure',
        'Cross-Site Request Forgery (CSRF)',
        'CSRF'
    ]

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


def run_scan_task(scan_id: int):
    app = create_app()
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            print(f"Error: Scan with ID {scan_id} not found.", flush=True)
            return

        print(f"Worker started for Scan ID: {scan_id}, Mode: {scan.scan_mode}", flush=True)
        scan.status = 'RUNNING'
        db.session.commit()

        seen_vuln_hashes = set()

        try:
            print(f"[Scan ID: {scan_id}] Starting Phase 0: Crawling & Site Tree Generation...", flush=True)
            scraped_urls = set()
            crawl_depth = 0 if scan.scan_mode == 'single' else 2

            if crawl_depth > 0:
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
                    out_file = tmp_file.name

                cmd = [
                    'scrapy', 'runspider', 'integrations/scrapy_spider.py',
                    '-a', f'target={scan.target_url}',
                    '-a', f'depth_limit={crawl_depth}',
                    '-o', out_file
                ]

                print(f"  [Scrapy] Running spider on {scan.target_url}...", flush=True)
                subprocess.run(cmd, capture_output=True)

                if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                    with open(out_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for item in data:
                            if 'url' in item:
                                scraped_urls.add(item['url'])

                if os.path.exists(out_file):
                    os.remove(out_file)

                site_tree = build_site_tree(list(scraped_urls))
                scan.site_tree = json.dumps(site_tree)
                db.session.commit()
                print(f"  [Scrapy] Found {len(scraped_urls)} unique URLs.", flush=True)
            else:
                scraped_urls.add(scan.target_url)

            print(f"[Scan ID: {scan_id}] Starting Phase 1: Reconnaissance...", flush=True)
            parsed_url = urlparse(scan.target_url)
            domain = parsed_url.hostname

            waf_result = run_wafw00f(scan.target_url)
            if waf_result:
                finding = ReconFinding(
                    scan_id=scan.id,
                    tool='wafw00f',
                    finding_type='WAF Detected',
                    details=json.dumps(waf_result)
                )
                db.session.add(finding)
                db.session.commit()

            if domain:
                dns_results = run_dnsrecon(domain)
                for record in dns_results:
                    rec_type = record.get('type', 'Unknown')
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='dnsrecon',
                        finding_type=f'DNS Record ({rec_type})',
                        details=json.dumps(record)
                    )
                    db.session.add(finding)
                db.session.commit()

            if domain:
                nmap_data = run_nmap(domain)

                for port_info in nmap_data.get('ports', []):
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='nmap',
                        finding_type='Open Port',
                        details=json.dumps(port_info)
                    )
                    db.session.add(finding)

                    product = port_info.get('product')
                    version = port_info.get('version')

                    if product and version:
                        print(f"  [Auditor] Checking {product} {version} on port {port_info.get('port')}...",
                              flush=True)
                        vulns = audit_service_version(product, version)

                        if vulns:
                            max_score = max([v.get('score', 0) for v in vulns]) if vulns else 0
                            severity = 'Low'
                            if max_score >= 9.0:
                                severity = 'Critical'
                            elif max_score >= 7.0:
                                severity = 'High'
                            elif max_score >= 4.0:
                                severity = 'Medium'

                            audit_details = {
                                'product': product,
                                'version': version,
                                'port': port_info.get('port'),
                                'cves': vulns
                            }

                            temp_vuln = VulnerabilityDataClass(
                                type='Outdated Service Component',
                                subcategory=f"{product} {version}",
                                url=f"{scan.target_url} (Port {port_info.get('port')})",
                                severity=severity,
                                details=audit_details
                            )

                            v_hash = _generate_dedup_hash(temp_vuln)
                            if v_hash not in seen_vuln_hashes:
                                kb_info = get_kb_info(temp_vuln.type)
                                cwe = kb_info.get('cwe', 'N/A')
                                cvss_vector = temp_vuln.cvss_vector or kb_info.get('cvss_vector')
                                cvss_score = temp_vuln.cvss_score

                                if cvss_vector:
                                    calculated_score, calc_severity = parse_and_calculate_cvss(cvss_vector)
                                    if calculated_score is not None:
                                        cvss_score = calculated_score
                                        severity = calc_severity

                                vulnerability_model = Vulnerability(
                                    scan_id=scan.id,
                                    type=temp_vuln.type,
                                    subcategory=temp_vuln.subcategory,
                                    url=temp_vuln.url,
                                    severity=severity,
                                    cvss_score=cvss_score,
                                    cvss_vector=cvss_vector,
                                    cwe=cwe,
                                    details=json.dumps(temp_vuln.details, indent=2)
                                )
                                db.session.add(vulnerability_model)
                                seen_vuln_hashes.add(v_hash)
                                print(f"  [Auditor] Found vulnerabilities for {product} {version}", flush=True)

                for vuln_info in nmap_data.get('vulnerabilities', []):
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='nmap-vuln',
                        finding_type=f"NSE: {vuln_info.get('script_id')}",
                        details=json.dumps(vuln_info)
                    )
                    db.session.add(finding)

                db.session.commit()

            print(f"[Scan ID: {scan_id}] Reconnaissance phase finished.", flush=True)

            print(f"[Scan ID: {scan_id}] Starting Phase 2: Nuclei scanning...", flush=True)
            nuclei_results = run_nuclei(scan.target_url)

            for n_vuln in nuclei_results:
                print(f"  [Scan ID: {scan_id}] Nuclei found: {n_vuln['type']}", flush=True)

                nuclei_temp = VulnerabilityDataClass(
                    type=f"[Nuclei] {n_vuln['type']}",
                    subcategory=n_vuln['details'].get('template_id'),
                    url=n_vuln['url'],
                    severity=n_vuln['severity'],
                    details=n_vuln['details']
                )

                v_hash = _generate_dedup_hash(nuclei_temp)
                if v_hash not in seen_vuln_hashes:
                    kb_info = get_kb_info(nuclei_temp.type)
                    cwe = kb_info.get('cwe', 'N/A')
                    cvss_vector = nuclei_temp.cvss_vector or kb_info.get('cvss_vector')
                    cvss_score = nuclei_temp.cvss_score
                    sev = nuclei_temp.severity

                    if cvss_vector:
                        calculated_score, calc_severity = parse_and_calculate_cvss(cvss_vector)
                        if calculated_score is not None:
                            cvss_score = calculated_score
                            sev = calc_severity

                    vulnerability_model = Vulnerability(
                        scan_id=scan.id,
                        type=nuclei_temp.type,
                        subcategory=nuclei_temp.subcategory,
                        url=nuclei_temp.url,
                        severity=sev,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        cwe=cwe,
                        details=json.dumps(nuclei_temp.details, indent=2)
                    )
                    db.session.add(vulnerability_model)
                    seen_vuln_hashes.add(v_hash)

            db.session.commit()

            print(f"[Scan ID: {scan_id}] Starting Phase 3: SQLMap scanning...", flush=True)
            sqlmap_results = run_sqlmap(scan.target_url, scan.auth_cookies)

            for result in sqlmap_results:
                print(f"  [Scan ID: {scan_id}] SQLMap found injection!", flush=True)

                vuln_count = len(result.get('findings', []))
                title = f"SQL Injection (Verified by sqlmap) - {vuln_count} points"

                kb_info = get_kb_info("SQL Injection")
                cwe = kb_info.get('cwe', 'N/A')
                cvss_vector = kb_info.get('cvss_vector')
                cvss_score = None
                sev = "Critical"

                if cvss_vector:
                    calculated_score, calc_severity = parse_and_calculate_cvss(cvss_vector)
                    if calculated_score is not None:
                        cvss_score = calculated_score
                        sev = calc_severity

                vulnerability_model = Vulnerability(
                    scan_id=scan.id,
                    type=title,
                    subcategory="Automated Exploitation",
                    url=scan.target_url,
                    severity=sev,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cwe=cwe,
                    details=json.dumps(result, indent=2)
                )
                db.session.add(vulnerability_model)

            db.session.commit()

            print(f"[Scan ID: {scan_id}] Starting Phase 4: Core Python Scanner...", flush=True)

            def save_vulnerability_callback(vuln: VulnerabilityDataClass):
                with app.app_context():
                    v_hash = _generate_dedup_hash(vuln)

                    if v_hash in seen_vuln_hashes:
                        return

                    print(f"  [Scan ID: {scan_id}] Found vulnerability: {vuln.type} on {vuln.url}", flush=True)

                    kb_info = get_kb_info(vuln.type)
                    cwe = kb_info.get('cwe', 'N/A')
                    cvss_vector = vuln.cvss_vector or kb_info.get('cvss_vector')
                    cvss_score = vuln.cvss_score
                    severity = vuln.severity

                    if cvss_vector:
                        calculated_score, calc_severity = parse_and_calculate_cvss(cvss_vector)
                        if calculated_score is not None:
                            cvss_score = calculated_score
                            severity = calc_severity

                    vulnerability_model = Vulnerability(
                        scan_id=scan.id,
                        type=vuln.type,
                        subcategory=getattr(vuln, 'subcategory', None),
                        url=vuln.url,
                        severity=severity,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        cwe=cwe,
                        details=json.dumps(vuln.details, indent=2, ensure_ascii=False)
                    )
                    db.session.add(vulnerability_model)
                    db.session.commit()

                    seen_vuln_hashes.add(v_hash)

            scanner_instance = Scanner(
                url=scan.target_url,
                cookies=scan.auth_cookies,
                depth=crawl_depth,
                pre_crawled_urls=scraped_urls
            )
            scanner_instance.scan(vulnerability_callback=save_vulnerability_callback)

            print(f"[Scan ID: {scan_id}] Starting Phase 5: AI Executive Summary...", flush=True)
            scan = db.session.get(Scan, scan_id)
            has_recon = bool(scan.recon_findings)
            has_vuln = bool(scan.vulnerabilities)

            if has_recon or has_vuln:
                vuln_summary = []

                for v in scan.vulnerabilities:
                    vuln_summary.append({'type': v.type, 'severity': v.severity})

                if has_recon:
                    for rf in scan.recon_findings:
                        if rf.tool == 'wafw00f':
                            details = rf.get_details_as_dict()
                            vuln_summary.append(
                                {'type': f"WAF Detected: {details.get('firewall', 'Unknown')}", 'severity': 'Info'})
                        elif rf.tool == 'nmap-vuln':
                            vuln_summary.append({'type': f"Nmap NSE: {rf.finding_type}", 'severity': 'High'})
                        elif rf.tool == 'nmap':
                            details = rf.get_details_as_dict()
                            vuln_summary.append(
                                {'type': f"Open Port: {details.get('port')}/{details.get('service_name')}",
                                 'severity': 'Info'})

                analysis_result = generate_overall_analysis(scan.target_url, vuln_summary)

                if analysis_result:
                    scan.ai_analysis = json.dumps(analysis_result, indent=2)
                    db.session.commit()
                    print(f"  [AI] Executive Summary generated.", flush=True)

            scan.status = 'COMPLETED'
            print(f"Scan ID: {scan_id} completed successfully.", flush=True)

        except Exception as e:
            print(f"Scan ID: {scan_id} for target {scan.target_url} failed.", flush=True)
            print(f"Error details: {e}", flush=True)
            traceback.print_exc()

            db.session.rollback()

            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = 'FAILED'

        finally:
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.end_time = datetime.now(timezone.utc)
                db.session.commit()
            print(f"Worker finished for Scan ID: {scan_id}", flush=True)