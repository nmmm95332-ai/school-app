import os, sqlite3, hmac, hashlib, secrets, logging
from datetime import date
from typing import Optional
import httpx, jwt
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

SECRET = os.getenv("SECRET_KEY", "change-me-in-production")
DB = os.getenv("DB_PATH", "school.db")
WA_TOKEN = os.getenv("WA_TOKEN", "")        # Meta WhatsApp Cloud API token
WA_PHONE_ID = os.getenv("WA_PHONE_ID", "")  # WhatsApp phone number ID
CC = os.getenv("COUNTRY_CODE", "222")       # كود الدولة الافتراضي (موريتانيا 222)
SCHOOL = os.getenv("SCHOOL_NAME", "المدرسة")
log = logging.getLogger("school")
app = FastAPI(title="School Manager")
bearer = HTTPBearer(auto_error=False)

# ---------- قاعدة البيانات ----------
def q(sql, args=(), one=False, write=False):
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(sql, args)
        if write:
            con.commit()
            return cur.lastrowid
        rows = [dict(r) for r in cur.fetchall()]
        return (rows[0] if rows else None) if one else rows
    finally:
        con.close()

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${h}"

def check_pw(pw, stored):
    salt, _ = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, salt), stored)

def init():
    for s in [
        """CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE,
           password TEXT, name TEXT, role TEXT, phone TEXT)""",
        """CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, name TEXT, grade TEXT,
           parent_id INTEGER, parent_phone TEXT, monthly_fee REAL DEFAULT 0, notes TEXT DEFAULT '')""",
        """CREATE TABLE IF NOT EXISTS fees(id INTEGER PRIMARY KEY, student_id INTEGER, month TEXT,
           amount REAL, paid REAL DEFAULT 0, UNIQUE(student_id, month))""",
        """CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY, student_id INTEGER,
           subject TEXT, day TEXT, status TEXT)""",
        """CREATE TABLE IF NOT EXISTS grades(id INTEGER PRIMARY KEY, student_id INTEGER, subject TEXT,
           exam TEXT, score REAL, max_score REAL, day TEXT)""",
        """CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, phone TEXT, body TEXT,
           status TEXT, at TEXT DEFAULT CURRENT_TIMESTAMP)""",
    ]:
        q(s, write=True)
    if not q("SELECT id FROM users WHERE username='admin'", one=True):
        q("INSERT INTO users(username,password,name,role) VALUES(?,?,?,?)",
          ("admin", hash_pw(os.getenv("ADMIN_PASSWORD", "admin123")), "المدير", "admin"), write=True)
init()

# ---------- المصادقة ----------
def need(*roles):
    def dep(c: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
        if not c:
            raise HTTPException(401, "يجب تسجيل الدخول")
        try:
            u = jwt.decode(c.credentials, SECRET, algorithms=["HS256"])
        except Exception:
            raise HTTPException(401, "انتهت الجلسة، سجّل الدخول من جديد")
        if roles and u["role"] not in roles:
            raise HTTPException(403, "ليست لديك صلاحية لهذا الإجراء")
        return u
    return dep

class Login(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def login(d: Login):
    u = q("SELECT * FROM users WHERE username=?", (d.username.strip(),), one=True)
    if not u or not check_pw(d.password, u["password"]):
        raise HTTPException(401, "اسم المستخدم أو كلمة المرور غير صحيحة")
    tok = jwt.encode({"id": u["id"], "role": u["role"], "name": u["name"]}, SECRET, algorithm="HS256")
    return {"token": tok, "role": u["role"], "name": u["name"]}

# ---------- واتساب ----------
def send_whatsapp(phone: str, body: str):
    p = "".join(ch for ch in (phone or "") if ch.isdigit())
    if not p:
        return
    if len(p) <= 8:
        p = CC + p
    status = "simulated"
    if WA_TOKEN and WA_PHONE_ID:
        try:
            r = httpx.post(
                f"https://graph.facebook.com/v20.0/{WA_PHONE_ID}/messages",
                headers={"Authorization": f"Bearer {WA_TOKEN}"},
                json={"messaging_product": "whatsapp", "to": p, "type": "text", "text": {"body": body}},
                timeout=15)
            status = "sent" if r.status_code < 300 else f"failed {r.status_code}"
        except Exception as e:
            status = f"error {e}"
    log.warning("WhatsApp -> %s [%s]: %s", p, status, body)
    q("INSERT INTO notifications(phone,body,status) VALUES(?,?,?)", (p, body, status), write=True)

def student_or_404(sid):
    s = q("SELECT * FROM students WHERE id=?", (sid,), one=True)
    if not s:
        raise HTTPException(404, "التلميذ غير موجود")
    return s

# ---------- المستخدمون ----------
class NewUser(BaseModel):
    username: str
    password: str
    name: str
    role: str
    phone: str = ""

@app.post("/api/users")
def add_user(d: NewUser, _=Depends(need("admin"))):
    if d.role not in ("teacher", "parent", "staff", "admin"):
        raise HTTPException(400, "دور غير صالح")
    if q("SELECT id FROM users WHERE username=?", (d.username,), one=True):
        raise HTTPException(400, "اسم المستخدم مستخدم من قبل")
    uid = q("INSERT INTO users(username,password,name,role,phone) VALUES(?,?,?,?,?)",
            (d.username, hash_pw(d.password), d.name, d.role, d.phone), write=True)
    return {"id": uid}

@app.get("/api/users")
def list_users(role: Optional[str] = None, _=Depends(need("admin", "staff"))):
    sql = "SELECT id,username,name,role,phone FROM users"
    return q(sql + (" WHERE role=?" if role else "") + " ORDER BY id DESC", (role,) if role else ())

@app.delete("/api/users/{uid}")
def del_user(uid: int, me=Depends(need("admin"))):
    if uid == me["id"]:
        raise HTTPException(400, "لا يمكنك حذف حسابك")
    q("DELETE FROM users WHERE id=?", (uid,), write=True)
    return {"ok": True}

# ---------- التلاميذ ----------
class NewStudent(BaseModel):
    name: str
    grade: str
    parent_id: Optional[int] = None
    parent_phone: str = ""
    monthly_fee: float = 0
    notes: str = ""

@app.get("/api/students")
def students(_=Depends(need("admin", "staff", "teacher"))):
    return q("""SELECT s.*, u.name AS parent_name FROM students s
                LEFT JOIN users u ON u.id=s.parent_id ORDER BY s.name""")

@app.post("/api/students")
def add_student(d: NewStudent, _=Depends(need("admin", "staff"))):
    sid = q("INSERT INTO students(name,grade,parent_id,parent_phone,monthly_fee,notes) VALUES(?,?,?,?,?,?)",
            (d.name, d.grade, d.parent_id, d.parent_phone, d.monthly_fee, d.notes), write=True)
    return {"id": sid}

@app.put("/api/students/{sid}")
def edit_student(sid: int, d: NewStudent, _=Depends(need("admin", "staff"))):
    student_or_404(sid)
    q("UPDATE students SET name=?,grade=?,parent_id=?,parent_phone=?,monthly_fee=?,notes=? WHERE id=?",
      (d.name, d.grade, d.parent_id, d.parent_phone, d.monthly_fee, d.notes, sid), write=True)
    return {"ok": True}

@app.delete("/api/students/{sid}")
def del_student(sid: int, _=Depends(need("admin"))):
    for t in ("fees", "attendance", "grades"):
        q(f"DELETE FROM {t} WHERE student_id=?", (sid,), write=True)
    q("DELETE FROM students WHERE id=?", (sid,), write=True)
    return {"ok": True}

# ---------- الرسوم ----------
def fee_status(f):
    if f["paid"] >= f["amount"]:
        return "paid"
    return "late" if f["month"] < date.today().strftime("%Y-%m") else "unpaid"

def fees_for(where="", args=()):
    rows = q(f"""SELECT f.*, s.name AS student_name, s.grade FROM fees f
                 JOIN students s ON s.id=f.student_id {where} ORDER BY f.month DESC, s.name""", args)
    for r in rows:
        r["status"] = fee_status(r)
    return rows

@app.get("/api/fees")
def get_fees(month: Optional[str] = None, _=Depends(need("admin", "staff"))):
    return fees_for("WHERE f.month=?", (month,)) if month else fees_for()

class Gen(BaseModel):
    month: str

@app.post("/api/fees/generate")
def gen_fees(d: Gen, _=Depends(need("admin", "staff"))):
    for s in q("SELECT id, monthly_fee FROM students"):
        q("INSERT OR IGNORE INTO fees(student_id,month,amount) VALUES(?,?,?)",
          (s["id"], d.month, s["monthly_fee"]), write=True)
    return {"ok": True}

class Pay(BaseModel):
    paid: float

@app.put("/api/fees/{fid}")
def pay_fee(fid: int, d: Pay, _=Depends(need("admin", "staff"))):
    q("UPDATE fees SET paid=? WHERE id=?", (d.paid, fid), write=True)
    return {"ok": True}

# ---------- الحضور والغياب ----------
class Att(BaseModel):
    student_id: int
    subject: str
    day: str = ""
    status: str = "absent"

@app.post("/api/attendance")
def add_att(d: Att, bg: BackgroundTasks, _=Depends(need("admin", "teacher"))):
    s = student_or_404(d.student_id)
    day = d.day or date.today().isoformat()
    q("INSERT INTO attendance(student_id,subject,day,status) VALUES(?,?,?,?)",
      (s["id"], d.subject, day, d.status), write=True)
    if d.status == "absent":
        par = q("SELECT phone FROM users WHERE id=?", (s["parent_id"],), one=True) if s["parent_id"] else None
        phone = s["parent_phone"] or (par or {}).get("phone", "")
        bg.add_task(send_whatsapp, phone,
                    f"السلام عليكم، نُعلمكم بأن ابنكم/ابنتكم {s['name']} تغيّب عن حصة {d.subject} بتاريخ {day}. — إدارة {SCHOOL}")
    return {"ok": True}

@app.get("/api/attendance")
def get_att(_=Depends(need("admin", "teacher", "staff"))):
    return q("""SELECT a.*, s.name AS student_name FROM attendance a
                JOIN students s ON s.id=a.student_id ORDER BY a.id DESC LIMIT 200""")

# ---------- النتائج ----------
class Grade(BaseModel):
    student_id: int
    subject: str
    exam: str
    score: float
    max_score: float = 20

@app.post("/api/grades")
def add_grade(d: Grade, bg: BackgroundTasks, _=Depends(need("admin", "teacher"))):
    s = student_or_404(d.student_id)
    q("INSERT INTO grades(student_id,subject,exam,score,max_score,day) VALUES(?,?,?,?,?,?)",
      (s["id"], d.subject, d.exam, d.score, d.max_score, date.today().isoformat()), write=True)
    par = q("SELECT phone FROM users WHERE id=?", (s["parent_id"],), one=True) if s["parent_id"] else None
    phone = s["parent_phone"] or (par or {}).get("phone", "")
    bg.add_task(send_whatsapp, phone,
                f"السلام عليكم، صدرت نتيجة {s['name']} في {d.subject} ({d.exam}): {d.score:g}/{d.max_score:g}. — إدارة {SCHOOL}")
    return {"ok": True}

@app.get("/api/grades")
def get_grades(_=Depends(need("admin", "teacher", "staff"))):
    return q("""SELECT g.*, s.name AS student_name FROM grades g
                JOIN students s ON s.id=g.student_id ORDER BY g.id DESC LIMIT 200""")

# ---------- ولي الأمر + لوحة المدير ----------
@app.get("/api/children")
def children(me=Depends(need("parent"))):
    out = []
    for s in q("SELECT * FROM students WHERE parent_id=?", (me["id"],)):
        out.append({
            "student": s,
            "fees": fees_for("WHERE f.student_id=?", (s["id"],)),
            "attendance": q("SELECT * FROM attendance WHERE student_id=? ORDER BY id DESC LIMIT 50", (s["id"],)),
            "grades": q("SELECT * FROM grades WHERE student_id=? ORDER BY id DESC LIMIT 50", (s["id"],)),
        })
    return out

@app.get("/api/stats")
def stats(_=Depends(need("admin"))):
    fees = fees_for()
    cnt = lambda st: sum(1 for f in fees if f["status"] == st)
    return {
        "students": q("SELECT COUNT(*) c FROM students", one=True)["c"],
        "teachers": q("SELECT COUNT(*) c FROM users WHERE role='teacher'", one=True)["c"],
        "parents": q("SELECT COUNT(*) c FROM users WHERE role='parent'", one=True)["c"],
        "paid": cnt("paid"), "late": cnt("late"), "unpaid": cnt("unpaid"),
        "collected": sum(f["paid"] for f in fees),
        "remaining": sum(max(f["amount"] - f["paid"], 0) for f in fees),
        "absences_today": q("SELECT COUNT(*) c FROM attendance WHERE day=? AND status='absent'",
                            (date.today().isoformat(),), one=True)["c"],
        "notifications": q("SELECT * FROM notifications ORDER BY id DESC LIMIT 8"),
    }

@app.get("/health")
def health():
    return {"ok": True}

app.mount("/", StaticFiles(directory="static", html=True), name="static")
