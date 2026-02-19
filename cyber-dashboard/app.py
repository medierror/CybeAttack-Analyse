"""
Cybersecurity Attack Detection Dashboard — Flask Application
"""

import os
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

from config import Config
from models import db, ScanLog, Threat
from detector import scan_file


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure required directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.join(app.instance_path), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    CORS(app)

    # Create tables
    with app.app_context():
        db.create_all()

    def allowed_file(filename):
        return (
            "." in filename
            and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS
        )

    # ─── Routes ─────────────────────────────────────────────

    @app.route("/")
    def index():
        """Serve the main dashboard page."""
        return render_template("index.html")

    @app.route("/api/upload", methods=["POST"])
    def upload_file():
        """
        Receive an uploaded log file, run the detector, save results
        to the database, and return JSON results to the frontend.
        """
        if "file" not in request.files:
            return jsonify({"error": "No file part in request"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        if not allowed_file(file.filename):
            return jsonify(
                {"error": f"File type not allowed. Use: {', '.join(Config.ALLOWED_EXTENSIONS)}"}
            ), 400

        # Save the uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        try:
            # ── Run the detector ──
            results = scan_file(filepath)

            # ── Save to database ──
            scan_log = ScanLog(
                filename=filename,
                total_lines=results["total_lines"],
                total_attacks=results["total_attacks"],
                clean_lines=results["clean_lines"],
                status="completed",
            )
            db.session.add(scan_log)
            db.session.flush()  # Get the ID before committing

            for threat_data in results["threats"]:
                threat = Threat(
                    scan_log_id=scan_log.id,
                    line_number=threat_data["line_number"],
                    attack_type=threat_data["attack_type"],
                    severity=threat_data["severity"],
                    matched_pattern=threat_data.get("matched_pattern"),
                    raw_line=threat_data["raw_line"],
                )
                db.session.add(threat)

            db.session.commit()

            # ── Return results ──
            return jsonify(
                {
                    "success": True,
                    "scan_id": scan_log.id,
                    "filename": filename,
                    "total_lines": results["total_lines"],
                    "total_attacks": results["total_attacks"],
                    "clean_lines": results["clean_lines"],
                    "threats": results["threats"],
                    "attack_summary": results["attack_summary"],
                    "severity_summary": results["severity_summary"],
                }
            )

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Processing failed: {str(e)}"}), 500

        finally:
            # Clean up uploaded file after processing
            if os.path.exists(filepath):
                os.remove(filepath)

    @app.route("/api/history", methods=["GET"])
    def get_history():
        """Return the scan history (most recent first)."""
        scans = ScanLog.query.order_by(ScanLog.upload_time.desc()).limit(20).all()
        return jsonify([s.to_dict() for s in scans])

    @app.route("/api/scan/<int:scan_id>", methods=["GET"])
    def get_scan(scan_id):
        """Return details for a specific scan including its threats."""
        scan = ScanLog.query.get_or_404(scan_id)
        data = scan.to_dict()
        data["threats"] = [t.to_dict() for t in scan.threats]

        attack_summary = {}
        severity_summary = {}
        for t in scan.threats:
            attack_summary[t.attack_type] = attack_summary.get(t.attack_type, 0) + 1
            severity_summary[t.severity] = severity_summary.get(t.severity, 0) + 1

        data["attack_summary"] = attack_summary
        data["severity_summary"] = severity_summary
        return jsonify(data)

    return app


if __name__ == "__main__":
    app = create_app()
    print("\n🛡️  Cybersecurity Dashboard running at http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
