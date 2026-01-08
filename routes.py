import json
import time
from flask import (Blueprint, Response, current_app, redirect, render_template,
                   request, url_for, abort)
from weasyprint import HTML

from factory import db, executor
from models import Scan
from tasks import run_scan_task

main_routes = Blueprint('main', __name__)


@main_routes.route('/')
def dashboard():
    scans = Scan.query.order_by(Scan.start_time.desc()).all()
    return render_template('dashboard.html', scans=scans)


@main_routes.route('/scan/new', methods=['POST'])
def new_scan():
    target_url = request.form.get('target_url')
    auth_cookies = request.form.get('auth_cookies')

    if not target_url or not target_url.strip():
        return "Target URL is required!", 400

    new_scan_obj = Scan(
        target_url=target_url.strip(),
        status='PENDING',
        auth_cookies=auth_cookies.strip() if auth_cookies else None
    )
    db.session.add(new_scan_obj)
    db.session.commit()

    executor.submit(run_scan_task, new_scan_obj.id)

    return redirect(url_for('main.scan_details', scan_id=new_scan_obj.id))


@main_routes.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)
    return render_template('scan_details.html', scan=scan)


@main_routes.route('/scan/<int:scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    scan_to_delete = db.session.get(Scan, scan_id)
    if scan_to_delete:
        db.session.delete(scan_to_delete)
        db.session.commit()
    return redirect(url_for('main.dashboard'))


@main_routes.route('/scan/<int:scan_id>/report/pdf')
def export_pdf(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)

    # 1. Tải Knowledge Base
    kb = {}
    try:
        with open('config/knowledge_base.yml', 'r', encoding='utf-8') as f:
            kb = yaml.safe_load(f)
    except Exception as e:
        print(f"Could not load knowledge base: {e}")

    # 2. "Làm giàu" dữ liệu lỗ hổng
    enriched_vulns = []
    for vuln in scan.vulnerabilities:
        # Tìm thông tin trong KB. Dùng startswith để khớp cả "[Nuclei] SQL Injection" với "SQL Injection"
        kb_info = kb.get('default')  # Default fallback
        for key, value in kb.items():
            if vuln.type.strip().startswith(key):
                kb_info = value
                break

        # Gắn thông tin KB vào đối tượng vuln để template dễ dùng
        vuln.kb_info = kb_info
        enriched_vulns.append(vuln)

    severity_counts = Counter(v.severity for v in enriched_vulns)

    html_string = render_template(
        'report_pdf.html',
        scan=scan,
        vulnerabilities=enriched_vulns,
        severity_counts=severity_counts
    )

    pdf = HTML(string=html_string).write_pdf()
    return Response(
        pdf,
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment;filename=Scan-Report-{scan_id}.pdf'
        }
    )


@main_routes.route('/stream/<int:scan_id>')
def stream(scan_id):
    def event_stream(app):
        sent_vuln_ids = set()
        while True:
            with app.app_context():
                scan = db.session.get(Scan, scan_id)
                if not scan:
                    break

                new_vulnerabilities = []
                for vuln in scan.vulnerabilities:
                    if vuln.id not in sent_vuln_ids:
                        new_vulnerabilities.append(vuln.to_dict())
                        sent_vuln_ids.add(vuln.id)

                payload = {
                    'status': scan.status,
                    'progress_message': f"Scanning... Found {len(sent_vuln_ids)} vulnerabilities so far.",
                    'new_vulnerabilities': new_vulnerabilities,
                    'start_time': scan.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else None,
                    'ai_analysis': json.loads(scan.ai_analysis) if scan.ai_analysis else None
                }

                status_completed = scan.status in ['COMPLETED', 'FAILED']

            yield f"data: {json.dumps(payload)}\n\n"

            if status_completed:
                break

            time.sleep(2)

    app_instance = current_app._get_current_object()
    return Response(event_stream(app_instance), mimetype='text/event-stream')