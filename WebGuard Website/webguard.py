from flask import Flask, render_template, Response, request, session, jsonify
import subprocess
import json
import logging
import threading
import queue
import uuid
import os
from datetime import timedelta
from collections import defaultdict

app = Flask(__name__)

# Secure session configuration
app.secret_key = os.urandom(24)  # Random secret key
app.permanent_session_lifetime = timedelta(hours=1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Active scans storage with thread management
active_scans = {}
scan_threads = defaultdict(dict)
scan_queues = defaultdict(dict)

@app.route("/")
@app.route("/home")
def home_page():
    return render_template('home.html')

@app.route("/attack_info")
def attack_info_page():
    return render_template('attack_info.html')

@app.route("/scanner")
def scanner_page():
    return render_template('scanner.html')

def run_scan(scanner_name, command, output_queue, scan_id):
    """Run a scan command and put output in the queue"""
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                output_queue.put((scanner_name, output.strip()))
        
        remaining_output = process.communicate()[0]
        if remaining_output:
            output_queue.put((scanner_name, remaining_output.strip()))
        
        output_queue.put((scanner_name, "SCAN_COMPLETE"))
    except Exception as e:
        output_queue.put((scanner_name, f"SCAN_ERROR: {str(e)}"))

@app.route("/start_scan", methods=["POST"])
def start_scan():
    data = request.json
    url = data.get("url")
    scan_type = data.get("scan_type")

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    # Create a unique scan ID or use existing one
    scan_id = data.get("scan_id", str(uuid.uuid4()))
    
    if scan_id not in active_scans:
        active_scans[scan_id] = {
            'url': url,
            'scan_type': scan_type,
            'results': [],
            'completed': False,
            'scanners': []
        }
        scan_queues[scan_id] = queue.Queue()

    # Start scanners if not already running
    scanners_to_start = []
    
    if scan_type == "all" or scan_type == "csrf":
        if "csrf" not in scan_threads[scan_id]:
            scanners_to_start.append(("csrf", ["python", "csrf.py", url]))
    
    if scan_type == "all" or scan_type == "sql":
        if "sql" not in scan_threads[scan_id]:
            scanners_to_start.append(("sql", ["python", "sql_injection.py", url]))

    for scanner_name, command in scanners_to_start:
        thread = threading.Thread(
            target=run_scan,
            args=(scanner_name, command, scan_queues[scan_id], scan_id),
            name=f"{scanner_name}-scanner-{scan_id}",
            daemon=True
        )
        thread.start()
        scan_threads[scan_id][scanner_name] = thread
        active_scans[scan_id]['scanners'].append(scanner_name)

    return jsonify({
        "scan_id": scan_id,
        "message": "Scan started successfully",
        "existing_results": active_scans[scan_id]['results']
    })

@app.route("/stream/<scan_id>")
def stream(scan_id):
    def generate():
        if scan_id not in active_scans or scan_id not in scan_queues:
            yield f"data: {json.dumps({'error': 'Invalid scan ID'})}\n\n"
            return

        # First send all existing results
        for result in active_scans[scan_id]['results']:
            yield f"data: {json.dumps({'message': result})}\n\n"

        # Then stream new results
        while True:
            try:
                scanner_name, message = scan_queues[scan_id].get(timeout=10)
                if message == "SCAN_COMPLETE":
                    active_scans[scan_id]['scanners'].remove(scanner_name)
                    if not active_scans[scan_id]['scanners']:
                        active_scans[scan_id]['completed'] = True
                        yield f"data: {json.dumps({'message': 'All scans completed', 'completed': True})}\n\n"
                        break
                else:
                    active_scans[scan_id]['results'].append(message)
                    yield f"data: {json.dumps({'message': message})}\n\n"
            except queue.Empty:
                # Check if all scanners are done
                if not scan_threads[scan_id] or all(not t.is_alive() for t in scan_threads[scan_id].values()):
                    active_scans[scan_id]['completed'] = True
                    yield f"data: {json.dumps({'message': 'Scan completed', 'completed': True})}\n\n"
                    break
                continue

    return Response(generate(), mimetype="text/event-stream")

@app.route("/get_scan/<scan_id>")
def get_scan(scan_id):
    scan_data = active_scans.get(scan_id, {})
    return jsonify({
        'url': scan_data.get('url'),
        'scan_type': scan_data.get('scan_type'),
        'results': scan_data.get('results', []),
        'completed': scan_data.get('completed', False)
    })

@app.route("/clear_scan/<scan_id>")
def clear_scan(scan_id):
    if scan_id in active_scans:
        # Clean up threads
        for thread in scan_threads.get(scan_id, {}).values():
            if thread.is_alive():
                thread.join(timeout=1)
        
        # Remove from storage
        del active_scans[scan_id]
        if scan_id in scan_threads:
            del scan_threads[scan_id]
        if scan_id in scan_queues:
            del scan_queues[scan_id]
    
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(debug=True)