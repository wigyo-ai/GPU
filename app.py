"""
app.py — Flask routing layer for the ATLAS Red Teaming Harness.

Environment variables required at runtime:
  H2OGPTE_URL     — base URL of the H2O GPTe deployment
  H2OGPTE_API_KEY — API key for authentication
  H2OGPTE_LLM     — (optional) model name; server default used if omitted
"""

import uuid
import logging
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()  # load .env if present

from flask import Flask, jsonify, render_template, request, session
import garak_integration as gi
import h2o_client

app = Flask(__name__)
app.secret_key = "atlas-red-team-harness-dev-key"  # replace with os.urandom(32) in prod

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# In-memory result store — keyed by UUID string.
# For production, replace with Redis / SQLite.
_results: dict[str, dict] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_technique(technique_id: str) -> tuple[dict | None, dict | None]:
    """Return (tactic_dict, technique_dict) for a given technique ID."""
    for tactic in gi.ATLAS_TAXONOMY.values():
        if technique_id in tactic["techniques"]:
            return tactic, tactic["techniques"][technique_id]
    return None, None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """ATLAS dashboard — lists all tactics and their techniques."""
    return render_template("index.html", taxonomy=gi.ATLAS_TAXONOMY)


@app.route("/technique/<technique_id>")
def technique(technique_id: str):
    """Payload editor page for a specific ATLAS technique."""
    tactic, tech = _find_technique(technique_id)
    if tech is None:
        return render_template("404.html"), 404

    return render_template(
        "technique.html",
        technique_id=technique_id,
        technique=tech,
        tactic=tactic,
    )


@app.route("/results/<result_id>")
def results(result_id: str):
    """Dedicated results page for a completed attack execution."""
    result = _results.get(result_id)
    if result is None:
        return render_template("404.html"), 404
    return render_template("results.html", result=result, result_id=result_id)


@app.route("/history")
def history():
    """Browse all past attack executions in the current server session."""
    items = sorted(_results.values(), key=lambda r: r["timestamp"], reverse=True)
    return render_template("history.html", results=items)


# ── JSON API ──────────────────────────────────────────────────────────────────

@app.route("/api/probes/<technique_id>")
def api_probes(technique_id: str):
    """Return the list of available Garak probe classes for a technique."""
    probes = gi.get_probes_for_technique(technique_id)
    return jsonify({"technique_id": technique_id, "probes": probes})


@app.route("/api/payloads")
def api_payloads():
    """
    Return prompts for a specific probe class.

    Query params:
      module — e.g. garak.probes.dan
      class  — e.g. Dan_11_0
    """
    module = request.args.get("module", "").strip()
    cls = request.args.get("class", "").strip()

    if not module or not cls:
        return jsonify({"error": "module and class query params are required"}), 400

    data = gi.get_payloads(module, cls)
    return jsonify(data)


@app.route("/api/execute", methods=["POST"])
def api_execute():
    """
    Execute an adversarial payload against H2O GPTe.

    Expected JSON body:
      {
          "technique_id":     str,
          "probe_module":     str,
          "probe_class":      str,
          "original_payload": str,
          "modified_payload": str,
          "system_prompt":    str  (optional)
      }

    Returns:
      {
          "result_id":        str,
          "verdict":          "SUCCESSFUL" | "BLOCKED" | "UNKNOWN",
          "confidence_pct":   int,
          "model_response":   str,
          "scoring":          dict,
          "error":            str | None
      }
    """
    body = request.get_json(force=True, silent=True) or {}

    technique_id = body.get("technique_id", "")
    probe_module = body.get("probe_module", "")
    probe_class = body.get("probe_class", "")
    original_payload = body.get("original_payload", "")
    modified_payload = body.get("modified_payload", "").strip()
    system_prompt = body.get("system_prompt", "").strip() or None

    if not modified_payload:
        return jsonify({"error": "modified_payload is required"}), 400

    tactic, tech = _find_technique(technique_id)

    # ── Send to H2O GPTe ──────────────────────────────────────────────────────
    logger.info("Executing payload for technique %s via %s.%s", technique_id, probe_module, probe_class)
    llm_result = h2o_client.send_prompt(modified_payload, system_prompt=system_prompt)

    model_response = llm_result.get("content") or ""
    llm_error = llm_result.get("error")

    # ── Score the response ────────────────────────────────────────────────────
    if llm_result["success"] and model_response:
        scoring = gi.score_response(model_response, technique_id)
    else:
        scoring = {
            "verdict": "UNKNOWN",
            "confidence_pct": 0,
            "refusal_score": 0,
            "compliance_score": 0,
            "signals": [],
            "garak_detector": None,
        }

    # ── Persist result ────────────────────────────────────────────────────────
    result_id = str(uuid.uuid4())
    _results[result_id] = {
        "result_id": result_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "technique_id": technique_id,
        "technique_name": tech["name"] if tech else technique_id,
        "tactic_name": tactic["name"] if tactic else "",
        "probe_module": probe_module,
        "probe_class": probe_class,
        "original_payload": original_payload,
        "modified_payload": modified_payload,
        "system_prompt": system_prompt or "",
        "model": llm_result.get("model", ""),
        "model_response": model_response,
        "llm_error": llm_error,
        "verdict": scoring["verdict"],
        "confidence_pct": scoring["confidence_pct"],
        "scoring": scoring,
    }

    logger.info("Result %s: verdict=%s confidence=%s%%", result_id, scoring["verdict"], scoring["confidence_pct"])

    return jsonify({
        "result_id": result_id,
        "verdict": scoring["verdict"],
        "confidence_pct": scoring["confidence_pct"],
        "model_response": model_response,
        "scoring": scoring,
        "error": llm_error,
    })


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
