import json
import time
import yaml
from collections import Counter
from urllib.parse import urlparse, urlunparse  # Đã thêm import parse URL

from flask import (Blueprint, Response, current_app, redirect, render_template,
                   request, url_for, abort, jsonify)
from weasyprint import HTML

from factory import db, executor
from models import Scan, Vulnerability
from tasks import run_scan_task
from integrations.ai_remediator import generate_remediation

main_routes = Blueprint('main', __name__)


@main_routes.route('/')
def dashboard():
    scans = Scan.query.order_by(Scan.start_time.desc()).all()
    return render_template('dashboard.html', scans=scans)


@main_routes.route('/scan/new', methods=['POST'])
def new_scan():
    # Lấy dữ liệu từ form
    target_url = request.form.get('target_url')
    auth_cookies = request.form.get('auth_cookies')
    scan_mode = request.form.get('scan_mode', 'full')

    if not target_url or not target_url.strip():
        return "Target URL is required!", 400

    target_url = target_url.strip()

    # --- TỰ ĐỘNG LÀM SẠCH URL ---
    # Thêm http:// nếu người dùng quên nhập
    parsed_url = urlparse(target_url)
    if not parsed_url.scheme:
        target_url = "http://" + target_url
        parsed_url = urlparse(target_url)

    # Loại bỏ fragment (ví dụ: #/login của Juice Shop/Angular)
    clean_url = urlunparse(parsed_url._replace(fragment=""))
    # -----------------------------

    # Lưu vào database
    new_scan_obj = Scan(
        target_url=clean_url,
        scan_mode=scan_mode,
        status='PENDING',
        auth_cookies=auth_cookies.strip() if auth_cookies else None
    )
    db.session.add(new_scan_obj)
    db.session.commit()

    # Gọi background worker
    executor.submit(run_scan_task, new_scan_obj.id)
    return redirect(url_for('main.scan_details', scan_id=new_scan_obj.id))


@main_routes.route('/api/remediate/<int:vuln_id>', methods=['POST'])
def api_remediate(vuln_id):
    vuln = db.session.get(Vulnerability, vuln_id)
    if not vuln:
        return jsonify({"error": "Vulnerability not found"}), 404

    try:
        details_dict = json.loads(vuln.details)
    except:
        details_dict = {}

    evidence = f"URL: {vuln.url}\nType: {vuln.type}\n"
    if 'parameter' in details_dict:
        evidence += f"Parameter: {details_dict['parameter']}\n"
    if 'payload' in details_dict:
        evidence += f"Payload: {details_dict['payload']}\n"

    ai_suggestion = generate_remediation(
        vulnerability_type=vuln.type,
        code_snippet=evidence,
        target_language="php"
    )

    if ai_suggestion and 'error' not in ai_suggestion:
        details_dict['ai_suggestion'] = ai_suggestion
        vuln.details = json.dumps(details_dict, ensure_ascii=False)
        db.session.commit()
        return jsonify({"status": "success", "data": ai_suggestion})
    else:
        return jsonify({"error": "AI failed to generate response"}), 500


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

    kb = {}
    try:
        with open('config/knowledge_base.yml', 'r', encoding='utf-8') as f:
            kb = yaml.safe_load(f)
    except Exception as e:
        print(f"Could not load knowledge base: {e}")

    enriched_vulns = []
    for vuln in scan.vulnerabilities:
        kb_info = kb.get('default')
        for key, value in kb.items():
            if vuln.type.strip().startswith(key):
                kb_info = value
                break
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
                }

                status_completed = scan.status in ['COMPLETED', 'FAILED']

            yield f"data: {json.dumps(payload)}\n\n"

            if status_completed:
                break

            time.sleep(2)

    app_instance = current_app._get_current_object()
    return Response(event_stream(app_instance), mimetype='text/event-stream')