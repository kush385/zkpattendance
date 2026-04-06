# ZKP Attendance (Flask Demo)

A demo **privacy-preserving attendance system** using a Schnorr-style Zero-Knowledge Proof flow.

Students prove they know a secret (`x`) linked to their public credential (`y`) without sending `x` to the server.

## Features

- Student registration with generated secret/public values
- Teacher challenge generation (`c`) per session
- Student proof generation (`t`, `s`) in browser flow
- Server-side verification of:
  - `g^s ≡ t * y^c (mod p)`
- Recent attendance log view

## Tech Stack

- Python 3
- Flask
- Jinja2 templates
- In-memory storage (no database)

## Project Structure

```text
zkp_attendance/
  app.py
  templates/
    base.html
    index.html
    register.html
    teacher.html
    student.html
    result.html
```

## Run Locally

From the project root:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install flask
python app.py
```

App URL: `http://127.0.0.1:5000`

## Usage Flow

1. Open `/register` and create a student ID.
2. Save the generated secret key `x` (shown once in UI).
3. Open `/teacher` and generate a challenge `c`.
4. Open `/student`, enter `student_id` and `x`, then generate proof.
5. Submit proof and review verification result on `/verify`.

## Protocol Notes

Current demo constants in `app.py`:

- `p = 23`
- `g = 5`
- `order = p - 1 = 22`

Proof generation:

- choose random `r`
- `t = g^r mod p`
- `s = (r + c*x) mod (p-1)`

Verification:

- accept if `g^s mod p == (t * y^c) mod p`

## Important Limitations

This is an educational demo, not production-ready:

- Small toy parameters (`p=23`) are cryptographically insecure
- Secret/session management is basic
- Data is stored in memory and resets on restart
- No persistent user/auth system

## File To Start With

- Main backend logic: `app.py`
- Frontend pages: `templates/*.html`
