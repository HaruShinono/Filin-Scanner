import json
import time
from flask import (Blueprint, Response, current_app, redirect, render_template,
                   request, url_for)

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
    if not target_url or not target_url.strip():
        return "Target URL is required!", 400

    new_scan_obj = Scan(target_url=target_url.strip(), status='PENDING')
    db.session.add(new_scan_obj)
    db.session.commit()

    executor.submit(run_scan_task, new_scan_obj.id)

    return redirect(url_for('main.scan_details', scan_id=new_scan_obj.id))


@main_routes.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template('scan_details.html', scan=scan)


@main_routes.route('/scan/<int:scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    scan_to_delete = Scan.query.get_or_404(scan_id)
    db.session.delete(scan_to_delete)
    db.session.commit()
    return redirect(url_for('main.dashboard'))


@main_routes.route('/stream/<int:scan_id>')
def stream(scan_id):
    def event_stream(app):
        sent_vuln_ids = set()
        while True:
            with app.app_context():
                scan = Scan.query.get(scan_id)
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
                    'end_time': scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else None
                }

                status_completed = scan.status in ['COMPLETED', 'FAILED']

            yield f"data: {json.dumps(payload)}\n\n"

            if status_completed:
                break

            time.sleep(2)

    app_instance = current_app._get_current_object()
    return Response(event_stream(app_instance), mimetype='text/event-stream')