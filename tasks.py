import json
import traceback
from datetime import datetime
from urllib.parse import urlparse

from factory import create_app, db
from models import ReconFinding, Scan, Vulnerability
from scanner_core.scanner import Scanner
from scanner_core.scanner import Vulnerability as VulnerabilityDataClass

from integrations.nmap_scanner import run_nmap
from integrations.wafw00f_scanner import run_wafw00f


def run_scan_task(scan_id: int):
    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            print(f"Error: Scan with ID {scan_id} not found.")
            return

        print(f"Worker started for Scan ID: {scan_id}, Target: {scan.target_url}")
        scan.status = 'RUNNING'
        db.session.commit()

        try:
            print(f"[Scan ID: {scan_id}] Starting reconnaissance phase...")
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
                nmap_results = run_nmap(domain)
                for port_info in nmap_results:
                    finding = ReconFinding(
                        scan_id=scan.id,
                        tool='nmap',
                        finding_type='Open Port',
                        details=json.dumps(port_info)
                    )
                    db.session.add(finding)
                db.session.commit()

            print(f"[Scan ID: {scan_id}] Reconnaissance phase finished.")

            def save_vulnerability_callback(vuln: VulnerabilityDataClass):
                with app.app_context():
                    print(f"  [Scan ID: {scan_id}] Found vulnerability: {vuln.type} at {vuln.url}")
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

            scanner_instance = Scanner(url=scan.target_url)
            scanner_instance.scan(vulnerability_callback=save_vulnerability_callback)

            scan.status = 'COMPLETED'
            print(f"Scan ID: {scan_id} completed successfully.")

        except Exception as e:
            print(f"Scan ID: {scan_id} for target {scan.target_url} failed.")
            print(f"Error details: {e}")
            traceback.print_exc()

            db.session.rollback()

            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'FAILED'

        finally:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.end_time = datetime.utcnow()
                db.session.commit()
            print(f"Worker finished for Scan ID: {scan_id}")