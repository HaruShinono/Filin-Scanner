import json
import traceback
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


def run_scan_task(scan_id: int):
    app = create_app()
    with app.app_context():
        # Use db.session.get() for SQLAlchemy 2.0 compatibility
        scan = db.session.get(Scan, scan_id)
        if not scan:
            print(f"Error: Scan with ID {scan_id} not found.", flush=True)
            return

        print(f"Worker started for Scan ID: {scan_id}, Target: {scan.target_url}", flush=True)
        scan.status = 'RUNNING'
        db.session.commit()

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

            # 3. Run Nmap (Ports, Service Audit, and NSE Scripts)
            if domain:
                nmap_data = run_nmap(domain)

                # A. Process Open Ports and Audit Services
                for port_info in nmap_data.get('ports', []):
                    # Save Port Finding
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='nmap',
                        finding_type='Open Port',
                        details=json.dumps(port_info)
                    )
                    db.session.add(finding)

                    # AUDIT: Check if service version is outdated/vulnerable via Vulners
                    product = port_info.get('product')
                    version = port_info.get('version')

                    if product and version:
                        print(f"  [Auditor] Checking {product} {version} on port {port_info.get('port')}...",
                              flush=True)
                        vulns = audit_service_version(product, version)

                        if vulns:
                            # Calculate severity based on Max CVSS Score
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

                            vulnerability_model = Vulnerability(
                                scan_id=scan.id,
                                type='Outdated Service Component',
                                subcategory=f"{product} {version}",
                                url=f"{scan.target_url} (Port {port_info.get('port')})",
                                severity=severity,
                                details=json.dumps(audit_details, indent=2)
                            )
                            db.session.add(vulnerability_model)
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

                vulnerability_model = Vulnerability(
                    scan_id=scan.id,
                    type=f"[Nuclei] {n_vuln['type']}",
                    subcategory=n_vuln['details'].get('template_id'),
                    url=n_vuln['url'],
                    severity=n_vuln['severity'],
                    details=json.dumps(n_vuln['details'], indent=2)
                )
                db.session.add(vulnerability_model)

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
                    print(f"  [Scan ID: {scan_id}] Found vulnerability: {vuln.type} at {vuln.url}", flush=True)
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

            # Initialize Scanner with Auth Cookies if available
            scanner_instance = Scanner(
                url=scan.target_url,
                cookies=scan.auth_cookies
            )
            scanner_instance.scan(vulnerability_callback=save_vulnerability_callback)

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
                # Use timezone-aware UTC
                scan.end_time = datetime.now(timezone.utc)
                db.session.commit()
            print(f"Worker finished for Scan ID: {scan_id}", flush=True)