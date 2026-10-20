"""
app.py
======
Threat Vector - Interactive Cybersecurity Awareness & Defensive Training Platform
---------------------------------------------------------------------------------
Technology Stack:
- Backend: Python Flask
- Database: SQLite (database.db)
- Machine Learning: Scikit-learn (TF-IDF + Logistic Regression in model.pkl)
- Frontend: HTML5 / CSS3 / Vanilla JavaScript (SOC Dark-Theme)

Single-link architecture: http://127.0.0.1:5000/
"""

import os
import json
import re
import joblib
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

from database import (
    init_db, get_db_connection, log_audit_event,
    DB_PATH, SCENARIOS_CSV
)
from train_model import train_and_export_model

# Initialize Flask Application
app = Flask(__name__)
app.secret_key = "threat-vector-super-secret-soc-key-2026"

# Ensure database exists and is populated
if not os.path.exists(DB_PATH):
    print("[*] Database not detected. Initializing SQLite tables & seed data...")
    init_db()

# Ensure ML model exists
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
if not os.path.exists(MODEL_PATH):
    print("[*] ML model not found. Training Scikit-learn classifier...")
    train_and_export_model(MODEL_PATH)

# Load Scikit-learn Model Pipeline
ml_pipeline = None
try:
    ml_pipeline = joblib.load(MODEL_PATH)
    print("[+] Scikit-learn Threat Classifier loaded successfully.")
except Exception as e:
    print(f"[-] Error loading ML model: {e}")


# ==============================================================================
# Helper Functions & User Context Decorators
# ==============================================================================

def get_current_user():
    """Fetches currently authenticated user object from SQLite."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

@app.before_request
def check_authentication():
    """
    Enforces login requirement across all protected routes.
    If trainee is unauthenticated, redirects directly to /login.
    """
    allowed_endpoints = ["login", "demo_login", "static"]
    if request.endpoint and request.endpoint not in allowed_endpoints:
        if not session.get("user_id"):
            flash("Please sign in or use Demo Login to access the SOC Training Range.", "warning")
            return redirect(url_for("login"))
    
    # Store user in flask.g for easy template access
    g.user = get_current_user()

@app.context_processor
def inject_global_data():
    """Injects current_user into all Jinja2 templates automatically."""
    return dict(current_user=g.user)


# ==============================================================================
# 1. Authentication & Session Routes
# ==============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    """Initial entry point: Sign in or Register new trainee profile."""
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        action = request.form.get("action", "login")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and passcode are required.", "danger")
            return render_template("login.html")

        conn = get_db_connection()

        if action == "login":
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                log_audit_event(user["id"], "Trainee Signed In", f"Username: {username}", request.remote_addr)
                conn.close()
                flash(f"Welcome to Threat Vector SOC, Analyst {username}!", "success")
                return redirect(url_for("index"))
            else:
                conn.close()
                flash("Invalid call-sign or passcode. Try demo account 'cadet' with password 'password123'.", "danger")
                return render_template("login.html")

        elif action == "register":
            role = request.form.get("role", "Security Cadet")
            existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                conn.close()
                flash(f"Call-sign '{username}' is already registered in the SOC database.", "danger")
                return render_template("login.html")

            pwd_hash = generate_password_hash(password)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password_hash, role, defense_score, drills_completed, ctf_completed, warroom_completed)
                VALUES (?, ?, ?, 0, 0, 0, 0)
            """, (username, pwd_hash, role))
            new_id = cursor.lastrowid
            conn.commit()
            conn.close()

            session["user_id"] = new_id
            session["username"] = username
            log_audit_event(new_id, "New Trainee Enrolled", f"Username: {username}, Role: {role}", request.remote_addr)
            flash(f"Trainee profile for '{username}' initialized! Welcome to Threat Vector.", "success")
            return redirect(url_for("index"))

    return render_template("login.html")

@app.route("/demo-login", methods=["POST"])
def demo_login():
    """One-click instant login as Cadet for college viva and project demonstrations."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = 'cadet'").fetchone()
    conn.close()

    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        log_audit_event(user["id"], "Demo Quick Login", "Authenticated as Cadet", request.remote_addr)
        flash("Quick Demo Login authenticated as Analyst 'cadet'!", "success")
    else:
        flash("Default demo account not found. Please register.", "danger")
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    """Logs out trainee and clears session."""
    user_id = session.get("user_id")
    if user_id:
        log_audit_event(user_id, "Trainee Signed Out", "", request.remote_addr)
    session.clear()
    flash("Session terminated safely. Defense credentials cleared.", "info")
    return redirect(url_for("login"))


# ==============================================================================
# 2. Main SOC Dashboard
# ==============================================================================

@app.route("/")
@app.route("/dashboard")
def index():
    """Main Dashboard: Overall defense metrics, readiness rating, 6 core feature cards, audit feed."""
    user = g.user
    conn = get_db_connection()

    # Total scenarios available
    total_drills = conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]

    # Calculate user accuracy %
    responses = conn.execute("""
        SELECT COUNT(*) as total, SUM(is_correct) as correct 
        FROM drill_responses WHERE user_id = ?
    """, (user["id"],)).fetchone()
    
    total_resp = responses["total"] or 0
    correct_resp = responses["correct"] or 0
    accuracy_pct = round((correct_resp / total_resp * 100), 1) if total_resp > 0 else 100.0

    # Calculate defense readiness rating (0 - 100)
    readiness_score = min(100, int((user["defense_score"] / 1000) * 50 + (accuracy_pct * 0.5)))
    if readiness_score >= 80:
        readiness_status = "High Defense Posture"
    elif readiness_score >= 50:
        readiness_status = "Moderate Resilience"
    else:
        readiness_status = "Developing Trainee"

    # User ranking on leaderboard
    all_users = conn.execute("SELECT id FROM users ORDER BY defense_score DESC").fetchall()
    user_rank = 1
    for idx, u in enumerate(all_users):
        if u["id"] == user["id"]:
            user_rank = idx + 1
            break

    # Recent Audit Logs
    audit_logs = conn.execute("""
        SELECT * FROM audit_logs 
        ORDER BY created_at DESC LIMIT 6
    """).fetchall()

    conn.close()

    return render_template(
        "index.html",
        active_page="dashboard",
        total_drills=total_drills,
        accuracy_pct=accuracy_pct,
        readiness_score=readiness_score,
        readiness_status=readiness_status,
        user_rank=user_rank,
        audit_logs=audit_logs
    )


# ==============================================================================
# 3. Interactive Drills (Continuous Simulation Flow)
# ==============================================================================

@app.route("/drills")
def drills():
    """
    Drill Runner: Loads scenario with continuous pagination.
    Drills NEVER run out or crash — if all completed, loops back to mastery cycling.
    """
    user = g.user
    scenario_id = request.args.get("scenario_id", type=int)
    category = request.args.get("category", "").strip()

    conn = get_db_connection()

    # Get all distinct categories
    cats_query = conn.execute("SELECT DISTINCT category FROM scenarios ORDER BY category").fetchall()
    all_categories = [c["category"] for c in cats_query]

    # Query targeted scenario
    if scenario_id:
        scenario = conn.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()
    elif category:
        scenario = conn.execute("SELECT * FROM scenarios WHERE category = ? ORDER BY id ASC LIMIT 1", (category,)).fetchone()
    else:
        # Continuous auto-selection: Find first drill user has NOT completed yet
        scenario = conn.execute("""
            SELECT s.* FROM scenarios s
            WHERE s.id NOT IN (SELECT scenario_id FROM drill_responses WHERE user_id = ?)
            ORDER BY s.id ASC LIMIT 1
        """, (user["id"],)).fetchone()

    # If all drills have been completed or none found, seamlessly cycle to Drill #1
    if not scenario:
        scenario = conn.execute("SELECT * FROM scenarios ORDER BY id ASC LIMIT 1").fetchone()

    # Count total scenarios & user's completed count
    total_scenarios = conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
    completed_count = conn.execute("SELECT COUNT(DISTINCT scenario_id) FROM drill_responses WHERE user_id = ?", (user["id"],)).fetchone()[0]
    progress_pct = min(100, round((completed_count / total_scenarios) * 100))

    # Parse potential indicators JSON for trainee checklist
    indicators = []
    try:
        indicators = json.loads(scenario["indicators_json"])
    except Exception:
        indicators = ["Lookalike sender address", "Artificial urgency", "Unverified external link", "Credential harvesting form"]

    conn.close()

    return render_template(
        "drill.html",
        active_page="drills",
        scenario=scenario,
        current_index=scenario["id"],
        total_scenarios=total_scenarios,
        completed_count=completed_count,
        progress_pct=progress_pct,
        all_categories=all_categories,
        selected_cat=category,
        indicators=indicators
    )

@app.route("/drills/next")
def next_drill():
    """
    Continuous Pagination Handler:
    Dynamically finds the next scenario without interruption.
    """
    user = g.user
    current_id = request.args.get("current_id", default=0, type=int)
    conn = get_db_connection()

    total_scenarios = conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]

    # 1. First priority: find next scenario with id > current_id that user hasn't answered
    next_scen = conn.execute("""
        SELECT id FROM scenarios 
        WHERE id > ? AND id NOT IN (SELECT scenario_id FROM drill_responses WHERE user_id = ?)
        ORDER BY id ASC LIMIT 1
    """, (current_id, user["id"])).fetchone()

    # 2. Second priority: find any scenario user hasn't answered
    if not next_scen:
        next_scen = conn.execute("""
            SELECT id FROM scenarios 
            WHERE id NOT IN (SELECT scenario_id FROM drill_responses WHERE user_id = ?)
            ORDER BY id ASC LIMIT 1
        """, (user["id"],)).fetchone()

    # 3. Third priority (mastery cycle): smoothly wrap around (current_id % total) + 1
    if not next_scen:
        next_id = (current_id % total_scenarios) + 1
        next_scen = conn.execute("SELECT id FROM scenarios WHERE id = ?", (next_id,)).fetchone()
        if not next_scen:
            next_scen = conn.execute("SELECT id FROM scenarios ORDER BY id ASC LIMIT 1").fetchone()

    conn.close()
    target_id = next_scen["id"] if next_scen else 1
    return redirect(url_for("drills", scenario_id=target_id))

@app.route("/drills/submit", methods=["POST"])
def submit_drill():
    """
    Evaluates trainee drill verdict & selected indicators.
    Awards defense points and displays explainable feedback.
    """
    user = g.user
    scenario_id = request.form.get("scenario_id", type=int)
    user_verdict = request.form.get("verdict", type=int)  # 1 = Malicious, 0 = Safe
    selected_indicators = request.form.getlist("indicators")

    conn = get_db_connection()
    scenario = conn.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()

    if not scenario:
        conn.close()
        flash("Scenario not found.", "danger")
        return redirect(url_for("drills"))

    is_correct = (user_verdict == scenario["is_malicious"])

    # Parse correct indicators
    correct_indicators = []
    try:
        correct_indicators = json.loads(scenario["correct_indicators_json"])
    except Exception:
        correct_indicators = []

    # Calculate matched indicators
    matched_indicators = [ind for ind in selected_indicators if ind in correct_indicators]

    # Points Calculation:
    # Base: scenario.points if verdict is correct, 0 if wrong
    # Bonus: +10 pts for each accurately identified indicator
    score_awarded = 0
    if is_correct:
        score_awarded = scenario["points"]
        # Indicator precision bonus
        score_awarded += len(matched_indicators) * 10
    else:
        score_awarded = 0

    # Record response in database
    conn.execute("""
        INSERT INTO drill_responses (user_id, scenario_id, user_verdict, is_correct, selected_indicators_json, score_awarded)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user["id"], scenario_id, user_verdict, 1 if is_correct else 0, json.dumps(selected_indicators), score_awarded))

    # Update user defense score & tally
    conn.execute("""
        UPDATE users 
        SET defense_score = defense_score + ?,
            drills_completed = drills_completed + 1
        WHERE id = ?
    """, (score_awarded, user["id"]))
    conn.commit()

    # Log audit event
    verdict_str = "Correct" if is_correct else "Incorrect"
    log_audit_event(
        user["id"],
        f"Drill #{scenario_id} Answered",
        f"Verdict: {verdict_str} (+{score_awarded} pts) | Category: {scenario['category']}",
        request.remote_addr
    )

    conn.close()

    # Render instant explainable feedback
    return render_template(
        "feedback.html",
        active_page="drills",
        scenario=scenario,
        is_correct=is_correct,
        score_awarded=score_awarded,
        selected_indicators=selected_indicators,
        matched_indicators=matched_indicators,
        correct_indicators=correct_indicators
    )


# ==============================================================================
# 4. AI Threat & Link Inspector (Scikit-learn ML Integration)
# ==============================================================================

def extract_heuristic_signals(text):
    """
    Deterministic rule engine checking for high-risk cybersecurity indicators:
    TLDs, urgent phrases, credential harvesting tokens, and typosquatting.
    """
    text_lower = text.lower()
    heuristics = []

    # 1. High-Risk TLDs check
    suspicious_tlds = [r"\.top", r"\.xyz", r"\.club", r"\.ru", r"\.biz", r"\.cc", r"\.link", r"\.tk", r"\.cf"]
    for tld in suspicious_tlds:
        if re.search(tld + r"(/|\s|$|\?)", text_lower):
            heuristics.append(f"High-Risk Top-Level Domain detected ({tld.replace(r'\\', '')})")
            break

    # 2. Urgency Panic Triggers
    urgency_patterns = ["urgent", "within 24 hours", "2 hours", "immediately", "expires today", "suspended", "action required"]
    for p in urgency_patterns:
        if p in text_lower:
            heuristics.append(f"High-urgency panic deadline detected ('{p}')")
            break

    # 3. Credential Solicitation
    cred_patterns = ["password", "otp", "pin", "ssn", "social security", "credit card", "gift card", "verify credentials"]
    for c in cred_patterns:
        if c in text_lower:
            heuristics.append(f"Credential harvesting solicitation keyword found ('{c}')")
            break

    # 4. Brand Impersonation / Typosquatting
    brand_spoofs = ["micros0ft", "paypa1", "wellsfargo-", "docusign.com.", "amazon-cancel", "netflix.billing"]
    for b in brand_spoofs:
        if b in text_lower:
            heuristics.append(f"Lookalike brand typosquatting signature detected ('{b}')")
            break

    # 5. Malicious Executables / Macro Attachments
    mal_exts = [".docm", ".exe", ".iso", ".vbs", ".ps1"]
    for ext in mal_exts:
        if ext in text_lower:
            heuristics.append(f"Potentially weaponized attachment format detected ('{ext}')")
            break

    return heuristics

@app.route("/inspector", methods=["GET", "POST"])
def inspector():
    """
    AI Threat & Link Inspector:
    Evaluates input text/URL using Scikit-learn TF-IDF + Logistic Regression pipeline
    augmented with deterministic heuristic security rules.
    """
    result = None
    input_text = ""

    if request.method == "POST":
        input_text = request.form.get("inspect_text", "").strip()

        if input_text and ml_pipeline:
            # 1. Run Scikit-learn ML inference
            probs = ml_pipeline.predict_proba([input_text])[0]
            malicious_prob = probs[1]  # Class 1 = Malicious
            safe_prob = probs[0]       # Class 0 = Safe

            # 2. Extract deterministic heuristic rules
            heuristics = extract_heuristic_signals(input_text)

            # 3. Hybrid decision logic (ML probability + heuristics)
            # If heuristics triggered, bump malicious confidence
            adjusted_prob = malicious_prob
            if heuristics:
                adjusted_prob = max(adjusted_prob, 0.78 + (len(heuristics) * 0.05))
                adjusted_prob = min(adjusted_prob, 0.99)

            is_malicious = adjusted_prob >= 0.50
            confidence = round((adjusted_prob if is_malicious else (1.0 - adjusted_prob)) * 100, 1)

            # 4. Extract top signal tokens from TF-IDF
            keywords = []
            try:
                tfidf = ml_pipeline.named_steps["tfidf"]
                clf = ml_pipeline.named_steps["clf"]
                feature_names = tfidf.get_feature_names_out()
                coefficients = clf.coef_[0]

                # Transform input text to find present tokens
                vec = tfidf.transform([input_text]).toarray()[0]
                present_indices = [i for i, val in enumerate(vec) if val > 0]

                # Sort present tokens by classifier weight
                weighted_tokens = sorted([(feature_names[i], coefficients[i]) for i in present_indices], key=lambda x: x[1], reverse=True)
                keywords = [t[0] for t in weighted_tokens[:5]]
            except Exception as e:
                keywords = ["urgent", "verify", "link", "password"]

            # 5. Formulate SOC Recommendation & MITRE Mapping
            if is_malicious:
                risk_level = "CRITICAL / HIGH RISK"
                mitre = "T1566.002 - Spearphishing Link / T1204 - User Execution"
                recommendation = "Quarantine message immediately. Do not click links or enter credentials. Block sender domain at the email gateway."
            else:
                risk_level = "LOW RISK / SAFE"
                mitre = "Benign Communication"
                recommendation = "Message appears authentic with legitimate institutional indicators. Verify domain certificates if sensitive transactions are requested."

            result = {
                "is_malicious": is_malicious,
                "confidence": confidence,
                "risk_level": risk_level,
                "heuristics": heuristics,
                "keywords": keywords,
                "mitre": mitre,
                "recommendation": recommendation
            }

            log_audit_event(
                g.user["id"],
                "AI Threat Inspector Query",
                f"Prediction: {risk_level} ({confidence}%)",
                request.remote_addr
            )

    return render_template(
        "inspector.html",
        active_page="inspector",
        input_text=input_text,
        result=result
    )


# ==============================================================================
# 5. CTF Tactical Range
# ==============================================================================

@app.route("/ctf")
def ctf():
    """Interactive CTF range displaying challenges and user capture status."""
    user = g.user
    conn = get_db_connection()

    challenges = conn.execute("SELECT * FROM ctf_challenges ORDER BY points ASC").fetchall()
    
    # Get solved challenge IDs for this user
    solved_rows = conn.execute("""
        SELECT DISTINCT challenge_id FROM ctf_submissions 
        WHERE user_id = ? AND is_correct = 1
    """, (user["id"],)).fetchall()
    solved_ids = [r["challenge_id"] for r in solved_rows]

    conn.close()

    return render_template(
        "ctf.html",
        active_page="ctf",
        challenges=challenges,
        solved_ids=solved_ids,
        solved_count=len(solved_ids)
    )

@app.route("/ctf/submit", methods=["POST"])
def submit_ctf():
    """Validates submitted CTF flag and awards defense points."""
    user = g.user
    challenge_id = request.form.get("challenge_id", type=int)
    submitted_flag = request.form.get("flag", "").strip()

    conn = get_db_connection()
    challenge = conn.execute("SELECT * FROM ctf_challenges WHERE id = ?", (challenge_id,)).fetchone()

    if not challenge:
        conn.close()
        flash("Challenge not found.", "danger")
        return redirect(url_for("ctf"))

    # Check if already solved
    already_solved = conn.execute("""
        SELECT id FROM ctf_submissions WHERE user_id = ? AND challenge_id = ? AND is_correct = 1
    """, (user["id"], challenge_id)).fetchone()

    if already_solved:
        conn.close()
        flash("You have already captured this flag!", "info")
        return redirect(url_for("ctf"))

    # Validate flag (case-insensitive strip)
    is_correct = (submitted_flag.lower() == challenge["flag"].strip().lower())

    conn.execute("""
        INSERT INTO ctf_submissions (user_id, challenge_id, submitted_flag, is_correct)
        VALUES (?, ?, ?, ?)
    """, (user["id"], challenge_id, submitted_flag, 1 if is_correct else 0))

    if is_correct:
        # Award points & increment ctf_completed
        conn.execute("""
            UPDATE users 
            SET defense_score = defense_score + ?,
                ctf_completed = ctf_completed + 1
            WHERE id = ?
        """, (challenge["points"], user["id"]))
        conn.commit()

        log_audit_event(
            user["id"],
            "CTF Flag Captured",
            f"Challenge: {challenge['title']} (+{challenge['points']} pts)",
            request.remote_addr
        )
        flash(f"🚩 FLAG CAPTURED! Outstanding work, Analyst. +{challenge['points']} defense points awarded!", "success")
    else:
        conn.commit()
        flash("❌ INCORRECT FLAG. Analyze the artifact closely, review the hint, and try again.", "danger")

    conn.close()
    return redirect(url_for("ctf"))


# ==============================================================================
# 6. Incident Response War Room
# ==============================================================================

@app.route("/war-room")
def war_room():
    """
    Incident Response War Room:
    Simulates multi-phase high-stakes breach containment scenarios.
    """
    user = g.user
    incident_id = request.args.get("incident_id", default=1, type=int)

    conn = get_db_connection()
    all_incidents = conn.execute("SELECT id, title, threat_type, severity FROM war_room_incidents ORDER BY id").fetchall()

    incident = conn.execute("SELECT * FROM war_room_incidents WHERE id = ?", (incident_id,)).fetchone()
    if not incident:
        incident = all_incidents[0]

    phases = json.loads(incident["phases_json"])
    total_phases = len(phases)

    # Check trainee's progress on this incident
    user_phase_logs = conn.execute("""
        SELECT * FROM war_room_logs 
        WHERE user_id = ? AND incident_id = ?
        ORDER BY phase_index ASC
    """, (user["id"], incident["id"])).fetchall()

    current_phase_index = len(user_phase_logs)
    incident_total_score = sum(log["points_earned"] for log in user_phase_logs)

    active_phase = phases[current_phase_index] if current_phase_index < total_phases else None

    conn.close()

    return render_template(
        "war_room.html",
        active_page="war_room",
        all_incidents=all_incidents,
        active_incident=incident,
        phases=phases,
        active_phase=active_phase,
        current_phase_index=current_phase_index,
        total_phases=total_phases,
        phase_history=user_phase_logs,
        incident_total_score=incident_total_score
    )

@app.route("/war-room/submit", methods=["POST"])
def submit_war_room_choice():
    """Processes tactical containment choice and advances to next phase."""
    user = g.user
    incident_id = request.form.get("incident_id", type=int)
    phase_index = request.form.get("phase_index", type=int)
    chosen_option_idx = request.form.get("chosen_option", type=int)

    conn = get_db_connection()
    incident = conn.execute("SELECT * FROM war_room_incidents WHERE id = ?", (incident_id,)).fetchone()

    if not incident:
        conn.close()
        flash("Incident not found.", "danger")
        return redirect(url_for("war_room"))

    phases = json.loads(incident["phases_json"])
    current_phase = phases[phase_index]
    chosen_opt = current_phase["options"][chosen_option_idx]

    points_earned = chosen_opt["points"]
    consequence_note = chosen_opt["consequence"]

    # Record log
    conn.execute("""
        INSERT INTO war_room_logs (user_id, incident_id, phase_index, chosen_option_index, points_earned, outcome_note)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user["id"], incident_id, phase_index, chosen_option_idx, points_earned, consequence_note))

    # Update user defense score
    conn.execute("""
        UPDATE users SET defense_score = MAX(0, defense_score + ?) WHERE id = ?
    """, (points_earned, user["id"]))

    # Check if this was the last phase
    if phase_index + 1 >= len(phases):
        conn.execute("""
            UPDATE users SET warroom_completed = warroom_completed + 1 WHERE id = ?
        """, (user["id"],))
        log_audit_event(
            user["id"],
            "Incident Response Contained",
            f"Incident: {incident['title']} Contained",
            request.remote_addr
        )
        flash(f"🚨 Tactical Containment Concluded! CSIRT post-mortem generated.", "success")
    else:
        flash(f"Command executed. Operational Outcome: {consequence_note}", "info")

    conn.commit()
    conn.close()

    return redirect(url_for("war_room", incident_id=incident_id))

@app.route("/war-room/reset")
def reset_war_room():
    """Resets user's progress on an incident to allow replay during viva."""
    user = g.user
    incident_id = request.args.get("incident_id", type=int)
    conn = get_db_connection()
    conn.execute("DELETE FROM war_room_logs WHERE user_id = ? AND incident_id = ?", (user["id"], incident_id))
    conn.commit()
    conn.close()
    flash("Incident state reset. You may run the containment simulation again.", "info")
    return redirect(url_for("war_room", incident_id=incident_id))


# ==============================================================================
# 7. Cybersecurity Defense Leaderboard
# ==============================================================================

@app.route("/leaderboard")
def leaderboard():
    """Global ranking table displaying trainee defense scores and accuracy."""
    user = g.user
    conn = get_db_connection()

    trainees = conn.execute("""
        SELECT * FROM users 
        ORDER BY defense_score DESC, drills_completed DESC
    """).fetchall()

    current_user_rank = 1
    for idx, t in enumerate(trainees):
        if t["id"] == user["id"]:
            current_user_rank = idx + 1
            break

    conn.close()

    return render_template(
        "leaderboard.html",
        active_page="leaderboard",
        trainees=trainees,
        current_user_rank=current_user_rank
    )


# ==============================================================================
# 8. Analytics & Risk Profile Dashboard
# ==============================================================================

@app.route("/profile")
def profile():
    """
    Personal Threat Readiness Analytics:
    Calculates category-wise accuracy, detects behavioral weaknesses,
    and displays printable defense certificate.
    """
    user = g.user
    conn = get_db_connection()

    # User overall drill stats
    user_responses = conn.execute("""
        SELECT dr.*, s.category, s.is_malicious 
        FROM drill_responses dr
        JOIN scenarios s ON dr.scenario_id = s.id
        WHERE dr.user_id = ?
    """, (user["id"],)).fetchall()

    total_responses = len(user_responses)
    correct_count = sum(1 for r in user_responses if r["is_correct"] == 1)
    misidentifications = total_responses - correct_count
    accuracy_pct = round((correct_count / total_responses * 100), 1) if total_responses > 0 else 100.0

    readiness_score = min(100, int((user["defense_score"] / 1000) * 50 + (accuracy_pct * 0.5)))

    # Category Breakdown
    cat_counts = {}
    for r in user_responses:
        cat = r["category"]
        if cat not in cat_counts:
            cat_counts[cat] = {"total": 0, "correct": 0}
        cat_counts[cat]["total"] += 1
        if r["is_correct"]:
            cat_counts[cat]["correct"] += 1

    # Ensure baseline categories appear even if not yet attempted
    all_known_cats = ["Phishing", "OTP Scams", "Impersonation", "Urgency", "Quishing/QR", "Tech Support", "Legitimate"]
    category_stats = []
    for c in all_known_cats:
        c_tot = cat_counts.get(c, {}).get("total", 0)
        c_cor = cat_counts.get(c, {}).get("correct", 0)
        pct = round((c_cor / c_tot * 100), 1) if c_tot > 0 else 100.0
        category_stats.append({
            "name": c,
            "total": c_tot,
            "correct": c_cor,
            "pct": int(pct)
        })

    # Weakness Diagnosis Logic
    # Find category with lowest accuracy among those with at least 1 attempt
    attempted_cats = [c for c in category_stats if c["total"] > 0]
    if attempted_cats:
        weakest = min(attempted_cats, key=lambda x: x["pct"])
        if weakest["pct"] < 70:
            primary_weakness_title = f"High Susceptibility to {weakest['name']} Vectors ({weakest['pct']}% Accuracy)"
            primary_weakness_detail = f"Evaluation reveals recurring misidentification in {weakest['name']} simulations. The trainee tends to overlook subtle indicator cues such as lookalike domain typosquatting and pressure-inducing deadlines."
            weakness_remediation = f"Focus targeted drill sessions on '{weakest['name']}' scenarios. Inspect sender domain SPF/DKIM authentication and cross-examine financial change requests out-of-band."
        else:
            primary_weakness_title = "Solid Cyber Hygiene & Balanced Posture"
            primary_weakness_detail = "Trainee displays consistent analytical vigilance across social engineering lures with detection rates exceeding 70% across all evaluated attack vectors."
            weakness_remediation = "Continue advancing to CTF Tactical Range challenges and War Room incident containment exercises to build tier-2 SOC skills."
    else:
        primary_weakness_title = "Baseline Assessment Pending"
        primary_weakness_detail = "Complete at least 3-5 simulation drills to generate personalized behavioral threat vulnerability diagnostics."
        weakness_remediation = "Navigate to the Drills module and complete your initial series of simulations."

    conn.close()

    return render_template(
        "profile.html",
        active_page="profile",
        total_responses=total_responses,
        correct_count=correct_count,
        misidentifications=misidentifications,
        accuracy_pct=accuracy_pct,
        readiness_score=readiness_score,
        category_stats=category_stats,
        primary_weakness_title=primary_weakness_title,
        primary_weakness_detail=primary_weakness_detail,
        weakness_remediation=weakness_remediation
    )


# ==============================================================================
# Application Server Entry Point
# ==============================================================================

if __name__ == "__main__":
    print("""
    ======================================================================
    ⚡ THREAT VECTOR - Cybersecurity Awareness & Defensive Training SOC ⚡
    ======================================================================
    [+] Server running locally on: http://127.0.0.1:5000/
    [+] Unified single-link architecture loaded.
    [+] Default Demo Account: cadet / password123
    ======================================================================
    """)
    app.run(debug=True, host="127.0.0.1", port=5000)
