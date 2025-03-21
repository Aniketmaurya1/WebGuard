from flask import Flask, render_template, Response, request
import subprocess
import json
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

@app.route("/stream")
def stream():
    # Get the URL and scan type from query parameters
    url = request.args.get("url")
    scan_type = request.args.get("scan_type")

    if scan_type not in ["all", "csrf"]:
        return json.dumps({"error": "This feature will be updated soon."}), 400

    # Function to generate real-time scan results
    def generate():
        logging.info(f"Starting scan for URL: {url}, Scan Type: {scan_type}")
        process = subprocess.Popen(
            ["python", "csrf.py", url],  # Run csrf.py with the target URL
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line-buffered output
            universal_newlines=True
        )
        for line in iter(process.stdout.readline, ''):
            logging.info(f"Scan output: {line.strip()}")
            yield f"data: {json.dumps({'message': line.strip()})}\n\n"
        process.stdout.close()
        process.wait()
        logging.info("Scan completed.")

    return Response(generate(), mimetype="text/event-stream")

if __name__ == '__main__':
    app.run(debug=True)