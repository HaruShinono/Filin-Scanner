import json
import traceback
import hashlib
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
from integrations.ai_remediator import generate_remediation, generate_overall_analysis


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

        print(f"Worker started for Scan ID: {scan_id}, Target: {scan.target_url}", flush=True)
        scan.status = 'RUNNING'
        db.session.commit()

        seen_vuln_hashes = set()

        try:
            # --- PHASE 1: RECONNAISSANCE ---
            print(f"[Scan ID: {scan_id}] Starting reconnaissance phase...", flush=True)
            parsed_url = urlparse(scan.target_url)
            domain = parsed_url.hostname

            # 1. Run WAFW00F
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

            # 2. Run DNSRecon
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

            # 3. Run Nmap
            if domain:
                nmap_data = run_nmap(domain)

                # A. Process Open Ports and Audit Services
                for port_info in nmap_data.get('ports', []):
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='nmap',
                        finding_type='Open Port',
                        details=json.dumps(port_info)
                    )
                    db.session.add(finding)

                    # AUDIT: Check service versions
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
                                vulnerability_model = Vulnerability(
                                    scan_id=scan.id,
                                    type=temp_vuln.type,
                                    subcategory=temp_vuln.subcategory,
                                    url=temp_vuln.url,
                                    severity=temp_vuln.severity,
                                    details=json.dumps(temp_vuln.details, indent=2)
                                )
                                db.session.add(vulnerability_model)
                                seen_vuln_hashes.add(v_hash)
                                print(f"  [Auditor] Found vulnerabilities for {product} {version}", flush=True)

                # B. Save Nmap Script Vulnerabilities
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

            # --- PHASE 2: NUCLEI SCANNING ---
            print(f"[Scan ID: {scan_id}] Running Nuclei scanner...", flush=True)
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
                    vulnerability_model = Vulnerability(
                        scan_id=scan.id,
                        type=nuclei_temp.type,
                        subcategory=nuclei_temp.subcategory,
                        url=nuclei_temp.url,
                        severity=nuclei_temp.severity,
                        details=json.dumps(nuclei_temp.details, indent=2)
                    )
                    db.session.add(vulnerability_model)
                    seen_vuln_hashes.add(v_hash)

            db.session.commit()

            # --- PHASE 3: SQLMAP SCANNING ---
            print(f"[Scan ID: {scan_id}] Running sqlmap (Check console for progress)...", flush=True)
            sqlmap_results = run_sqlmap(scan.target_url, scan.auth_cookies)

            for result in sqlmap_results:
                print(f"  [Scan ID: {scan_id}] SQLMap found injection!", flush=True)

                vuln_count = len(result.get('findings', []))
                title = f"SQL Injection (Verified by sqlmap) - {vuln_count} points"

                vulnerability_model = Vulnerability(
                    scan_id=scan.id,
                    type=title,
                    subcategory="Automated Exploitation",
                    url=scan.target_url,
                    severity="Critical",
                    details=json.dumps(result, indent=2)
                )
                db.session.add(vulnerability_model)

            db.session.commit()

            # --- PHASE 4: CORE PYTHON SCANNING ---
            print(f"[Scan ID: {scan_id}] Starting Core Python Scanner...", flush=True)

            def save_vulnerability_callback(vuln: VulnerabilityDataClass):
                with app.app_context():
                    v_hash = _generate_dedup_hash(vuln)

                    if v_hash in seen_vuln_hashes:
                        return

                    print(f"  [Scan ID: {scan_id}] Found vulnerability: {vuln.type} on {vuln.url}", flush=True)

                    # --- INDIVIDUAL AI REMEDIATION (UPDATED) ---
                    # 1. Bỏ bộ lọc AI_TARGETS -> Cho phép mọi lỗ hổng chạy AI
                    print(f"  [AI] Triggering individual fix for: {vuln.type}", flush=True)
                    evidence = f"URL: {vuln.url}\nType: {vuln.type}\n"
                    if isinstance(vuln.details, dict):
                        if 'parameter' in vuln.details:
                            evidence += f"Parameter: {vuln.details['parameter']}\n"
                        if 'payload' in vuln.details:
                            evidence += f"Payload: {vuln.details['payload']}\n"
                        if 'issue' in vuln.details:
                            evidence += f"Issue Details: {vuln.details['issue']}\n"
                        # Thêm một chút chi tiết thô để AI hiểu rõ hơn
                        evidence += f"Full Details Snippet: {str(vuln.details)[:300]}"

                    ai_suggestion = generate_remediation(
                        vulnerability_type=vuln.type,
                        code_snippet=evidence,
                        target_language="php"  # Bạn có thể thêm logic detect language từ Nmap/Wappalyzer sau này
                    )

                    if ai_suggestion:
                        vuln.details['ai_suggestion'] = ai_suggestion
                    # ---------------------------------------------

                    vulnerability_model = Vulnerability(
                        scan_id=scan.id,
                        type=vuln.type,
                        subcategory=getattr(vuln, 'subcategory', None),
                        url=vuln.url,
                        severity=vuln.severity,
                        details=json.dumps(vuln.details, indent=2, ensure_ascii=False)
                    )
                    db.session.add(vulnerability_model)
                    db.session.commit()

                    seen_vuln_hashes.add(v_hash)

            scanner_instance = Scanner(
                url=scan.target_url,
                cookies=scan.auth_cookies
            )
            scanner_instance.scan(vulnerability_callback=save_vulnerability_callback)

            # --- PHASE 5: AI EXECUTIVE SUMMARY (UPDATED) ---
            # Refresh scan object to get all new vulnerabilities
            scan = db.session.get(Scan, scan_id)
            has_recon = bool(scan.recon_findings)
            has_vuln = bool(scan.vulnerabilities)

            if has_recon or has_vuln:
                print(f"[Scan ID: {scan_id}] Generating AI Executive Summary...", flush=True)

                vuln_summary = []

                # + Application Vulners
                for v in scan.vulnerabilities:
                    vuln_summary.append({'type': v.type, 'severity': v.severity})

                # + Recon Findings -> Summary
                if has_recon:
                    for rf in scan.recon_findings:
                        # WAF
                        if rf.tool == 'wafw00f':
                            details = rf.get_details_as_dict()
                            vuln_summary.append(
                                {'type': f"WAF Detected: {details.get('firewall', 'Unknown')}", 'severity': 'Info'})
                        # Nmap Vulnerabilities (Critical)
                        elif rf.tool == 'nmap-vuln':
                            vuln_summary.append({'type': f"Nmap NSE: {rf.finding_type}", 'severity': 'High'})
                        # Open Ports (Infrastructure)
                        elif rf.tool == 'nmap':
                            details = rf.get_details_as_dict()
                            vuln_summary.append(
                                {'type': f"Open Port: {details.get('port')}/{details.get('service_name')}",
                                 'severity': 'Info'})

                # Gọi AI Summary với danh sách tổng hợp
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