"""
Privacy-Preserving Attendance System using Zero-Knowledge Proofs
================================================================
Cryptographic Parameters (demo only — NOT production-grade):
  p = 23  (prime modulus)
  g = 5   (generator)

Schnorr Identification Protocol:
  Register : y = g^x mod p          (x = secret, y = public credential)
  Prove    : t = g^r, s = r + c*x   (mod p-1, by Fermat's little theorem)
  Verify   : g^s ≡ t · y^c (mod p)
"""

import random
from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)
app.secret_key = "zkp-demo-secret-not-for-production"

# ── Cryptographic constants ──────────────────────────────────────────────────
P = 23          # prime modulus
G = 5           # generator  (ord(G) = P-1 = 22 in Z_P*)
ORDER = P - 1   # order of G (22)

# ── In-memory storage ────────────────────────────────────────────────────────
students = {}       # { student_id: { "y": int } }
challenge_store = {}  # { session_id: int }   (one challenge per teacher session)
attendance_log = []   # list of dicts for display


# ── Helper ───────────────────────────────────────────────────────────────────
def mod_pow(base, exp, mod):
    return pow(base, exp, mod)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ---------- Registration ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    student_id = request.form.get("student_id", "").strip()
    if not student_id:
        return render_template("register.html", error="Student ID cannot be empty.")
    if student_id in students:
        return render_template("register.html",
                               error=f"'{student_id}' is already registered.")

    # Generate secret key x and public credential y
    x = random.randint(2, ORDER - 1)          # secret ∈ {2 … ORDER-1}
    y = mod_pow(G, x, P)                       # public  y = g^x mod p

    students[student_id] = {"y": y}

    return render_template("register.html",
                           success=True,
                           student_id=student_id,
                           x=x,
                           y=y,
                           g=G,
                           p=P)


# ---------- Teacher — generate challenge ----------

@app.route("/teacher", methods=["GET"])
def teacher():
    return render_template("teacher.html",
                           students=list(students.keys()),
                           challenge=challenge_store.get("current"),
                           log=attendance_log[-10:])


@app.route("/generate_challenge", methods=["POST"])
def generate_challenge():
    c = random.randint(2, ORDER - 1)
    challenge_store["current"] = c
    return jsonify({"challenge": c, "status": "ok"})


# ---------- Student — submit proof ----------

@app.route("/student", methods=["GET"])
def student():
    c = challenge_store.get("current")
    return render_template("student.html", challenge=c, g=G, p=P, order=ORDER)


@app.route("/submit_proof", methods=["POST"])
def submit_proof():
    """
    Receives: student_id, x (secret), challenge c
    Computes: r (random), t = g^r mod p, s = (r + c*x) mod (p-1)
    Returns:  r, t, s  — browser then calls /verify with (student_id, t, s)
    """
    student_id = request.form.get("student_id", "").strip()
    x_str      = request.form.get("x", "").strip()
    c_str      = request.form.get("c", "").strip()

    # Input validation
    if not student_id or not x_str or not c_str:
        return jsonify({"error": "Missing fields."}), 400
    if student_id not in students:
        return jsonify({"error": f"Student '{student_id}' not registered."}), 400

    try:
        x = int(x_str)
        c = int(c_str)
    except ValueError:
        return jsonify({"error": "x and c must be integers."}), 400

    if c != challenge_store.get("current"):
        return jsonify({"error": "Challenge mismatch — generate a fresh challenge."}), 400

    # Proof generation
    r = random.randint(2, ORDER - 1)
    t = mod_pow(G, r, P)                   # t = g^r mod p
    s = (r + c * x) % ORDER               # s = (r + c·x) mod (p-1)

    return jsonify({
        "student_id": student_id,
        "r": r,
        "t": t,
        "s": s,
        "c": c,
        "g": G,
        "p": P,
        "order": ORDER,
        "steps": {
            "r_chosen":       f"r = {r}  (random ∈ [2, {ORDER-1}])",
            "t_computed":     f"t = g^r mod p = {G}^{r} mod {P} = {t}",
            "s_computed":     f"s = (r + c·x) mod (p-1) = ({r} + {c}·{x}) mod {ORDER} = {s}",
        }
    })


# ---------- Verification ----------

@app.route("/verify", methods=["POST"])
def verify():
    student_id = request.form.get("student_id", "").strip()
    t_str      = request.form.get("t", "").strip()
    s_str      = request.form.get("s", "").strip()

    if not student_id or not t_str or not s_str:
        return render_template("result.html", success=False,
                               error="Missing fields.", log=attendance_log[-10:])
    if student_id not in students:
        return render_template("result.html", success=False,
                               error=f"Student '{student_id}' not found.",
                               log=attendance_log[-10:])

    t = int(t_str)
    s = int(s_str)
    c = challenge_store.get("current")

    if c is None:
        return render_template("result.html", success=False,
                               error="No active challenge. Ask teacher to generate one.",
                               log=attendance_log[-10:])

    y   = students[student_id]["y"]
    lhs = mod_pow(G, s, P)                  # g^s mod p
    rhs = (t * mod_pow(y, c, P)) % P        # (t · y^c) mod p

    success = (lhs == rhs)

    # Build step-by-step equation trace
    steps = {
        "lhs_expr":  f"g^s mod p  =  {G}^{s} mod {P}  =  {lhs}",
        "rhs_expr":  f"(t · y^c) mod p  =  ({t} · {y}^{c}) mod {P}  =  {rhs}",
        "equation":  f"{lhs}  {'==' if success else '≠'}  {rhs}  →  {'✓ VALID' if success else '✗ INVALID'}",
    }

    entry = {
        "student_id": student_id,
        "result": "✓ PRESENT" if success else "✗ REJECTED",
        "lhs": lhs,
        "rhs": rhs,
        "success": success,
    }
    attendance_log.append(entry)

    return render_template("result.html",
                           success=success,
                           student_id=student_id,
                           t=t, s=s, c=c, y=y, g=G, p=P,
                           lhs=lhs, rhs=rhs,
                           steps=steps,
                           log=attendance_log[-10:])


if __name__ == "__main__":
    app.run(debug=True, port=5000)
