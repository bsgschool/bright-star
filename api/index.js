const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});
const secret = process.env.AUTH_TOKEN_SECRET;
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const fail = (res, status, error) => res.status(status).json({ error });
const dbRequired = (req, res, next) => process.env.DATABASE_URL ? next() : fail(res, 503, "DATABASE_URL is not configured.");
const str = (v, field, max=200, required=true) => {
  if (v == null) { if (!required) return null; throw new Error(field + " is required."); }
  const s = String(v).trim();
  if (required && !s) throw new Error(field + " is required.");
  if (s.length > max) throw new Error(field + " must be " + max + " characters or fewer.");
  return s || null;
};
const int = (v, field) => {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) throw new Error(field + " must be a positive integer.");
  return n;
};
const num = (v, field) => {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) throw new Error(field + " must be a non-negative number.");
  return n;
};
function tokenFor(user) {
  if (!secret || secret.length < 32) throw new Error("AUTH_TOKEN_SECRET must be at least 32 characters.");
  const b64 = x => Buffer.from(JSON.stringify(x)).toString("base64url");
  const head = b64({alg:"HS256",typ:"JWT"});
  const now = Math.floor(Date.now()/1000);
  const body = b64({sub:String(user.id),email:user.email,role:user.role,iat:now,exp:now+28800});
  const raw = head + "." + body;
  return raw + "." + crypto.createHmac("sha256", secret).update(raw).digest("base64url");
}
function verifyToken(value) {
  if (!secret || secret.length < 32) return null;
  const p = String(value || "").split(".");
  if (p.length !== 3) return null;
  const expected = crypto.createHmac("sha256", secret).update(p[0]+"."+p[1]).digest();
  const actual = Buffer.from(p[2], "base64url");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try { const u=JSON.parse(Buffer.from(p[1],"base64url").toString()); return u.exp > Date.now()/1000 ? u : null; } catch (_) { return null; }
}
const admin = (req,res,next) => {
  const m=(req.headers.authorization||"").match(/^Bearer\s+(.+)$/i);
  const u=m && verifyToken(m[1]);
  if (!u || u.role!=="admin") return fail(res,401,"Admin authentication required.");
  req.authUser=u; next();
};
async function checkPassword(password, stored) {
  const p=String(stored||"").split("$");
  if (p.length!==4 || p[0]!=="scrypt") return false;
  const salt=Buffer.from(p[2],"base64url"), expected=Buffer.from(p[3],"base64url");
  const actual=await new Promise((resolve,reject)=>crypto.scrypt(password,salt,expected.length,(e,k)=>e?reject(e):resolve(k)));
  return actual.length===expected.length && crypto.timingSafeEqual(actual,expected);
}

app.get("/api", (_req,res)=>res.json({status:"Bright Star School API is Ready"}));
app.get("/api/health", wrap(async (_req,res)=>{
  if (!process.env.DATABASE_URL) return res.json({ok:true,databaseConfigured:false,message:"API is running; DATABASE_URL is not configured."});
  try { await pool.query("SELECT 1"); res.json({ok:true,databaseConfigured:true,database:"PostgreSQL"}); }
  catch (_) { fail(res,503,"Database connection failed."); }
}));
app.post("/api/auth/login", dbRequired, wrap(async(req,res)=>{
  const email=str(req.body?.email,"email",254).toLowerCase(), password=str(req.body?.password,"password",1024);
  if (!secret || secret.length<32) return fail(res,503,"Set AUTH_TOKEN_SECRET to a random secret of at least 32 characters.");
  const q=await pool.query("SELECT id,email,password_hash,role FROM users WHERE lower(email)=lower($1) LIMIT 1",[email]);
  const u=q.rows[0];
  if (!u || u.role!=="admin" || !(await checkPassword(password,u.password_hash))) return fail(res,401,"Invalid email or password.");
  res.json({token:tokenFor(u),user:{id:u.id,email:u.email,role:u.role}});
}));

app.get("/api/students",dbRequired,wrap(async(_req,res)=>res.json((await pool.query("SELECT id,name,class,roll_no,father_name,contact,created_at FROM students ORDER BY name")).rows)));
app.post("/api/students",dbRequired,admin,wrap(async(req,res)=>{
  const v=[str(req.body.name,"name",160),str(req.body.class,"class",80),str(req.body.roll_no,"roll_no",40),str(req.body.father_name,"father_name",160,false),str(req.body.contact,"contact",40,false)];
  const q=await pool.query("INSERT INTO students(name,class,roll_no,father_name,contact) VALUES($1,$2,$3,$4,$5) RETURNING *",v); res.status(201).json(q.rows[0]);
}));
app.get("/api/teachers",dbRequired,wrap(async(_req,res)=>res.json((await pool.query("SELECT id,name,subject,created_at FROM teachers ORDER BY name")).rows)));
app.post("/api/teachers",dbRequired,admin,wrap(async(req,res)=>{
  const q=await pool.query("INSERT INTO teachers(name,subject) VALUES($1,$2) RETURNING *",[str(req.body.name,"name",160),str(req.body.subject,"subject",120)]);res.status(201).json(q.rows[0]);
}));
app.get("/api/classes",dbRequired,wrap(async(_req,res)=>res.json((await pool.query("SELECT id,name,section,room,class_teacher,created_at FROM classes ORDER BY sort_order,name,section")).rows)));

app.get("/api/fees",dbRequired,wrap(async(req,res)=>{
  const id=req.query.student_id ? int(req.query.student_id,"student_id") : null;
  const q=await pool.query("SELECT f.*,s.name AS student_name FROM fees f JOIN students s ON s.id=f.student_id "+(id?"WHERE f.student_id=$1 ":"")+"ORDER BY f.created_at DESC LIMIT 500",id?[id]:[]);
  res.json(q.rows);
}));
app.post("/api/fees",dbRequired,admin,wrap(async(req,res)=>{
  const status=str(req.body.status||"unpaid","status",20).toLowerCase();
  if(!["paid","unpaid","partial","waived"].includes(status))return fail(res,400,"Invalid fee status.");
  const q=await pool.query("INSERT INTO fees(student_id,amount,month,status,paid_at,notes) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",
    [int(req.body.student_id,"student_id"),num(req.body.amount,"amount"),str(req.body.month,"month",20),status,status==="paid"?new Date():null,str(req.body.notes,"notes",1000,false)]);
  res.status(201).json(q.rows[0]);
}));
app.patch("/api/fees/:id",dbRequired,admin,wrap(async(req,res)=>{
  const status=str(req.body.status,"status",20).toLowerCase();if(!["paid","unpaid","partial","waived"].includes(status))return fail(res,400,"Invalid fee status.");
  const q=await pool.query("UPDATE fees SET status=$1,paid_at=CASE WHEN $1='paid' THEN COALESCE(paid_at,NOW()) ELSE NULL END WHERE id=$2 RETURNING *",[status,int(req.params.id,"id")]);
  if(!q.rowCount)return fail(res,404,"Fee record not found.");res.json(q.rows[0]);
}));
app.delete("/api/fees/:id",dbRequired,admin,wrap(async(req,res)=>{const q=await pool.query("DELETE FROM fees WHERE id=$1 RETURNING id",[int(req.params.id,"id")]);if(!q.rowCount)return fail(res,404,"Fee record not found.");res.json({deleted:true,id:q.rows[0].id});}));

app.get("/api/attendance",dbRequired,wrap(async(req,res)=>{
  const date=req.query.date?str(req.query.date,"date",10):null;
  const q=await pool.query("SELECT a.*,s.name AS student_name,s.class FROM attendance a JOIN students s ON s.id=a.student_id "+(date?"WHERE a.attendance_date=$1::date ":"")+"ORDER BY a.attendance_date DESC LIMIT 1000",date?[date]:[]);
  res.json(q.rows);
}));
app.post("/api/attendance",dbRequired,admin,wrap(async(req,res)=>{
  const status=str(req.body.status,"status",20).toLowerCase();if(!["present","absent","late","leave"].includes(status))return fail(res,400,"Invalid attendance status.");
  const q=await pool.query("INSERT INTO attendance(student_id,attendance_date,status,notes) VALUES($1,$2::date,$3,$4) ON CONFLICT(student_id,attendance_date) DO UPDATE SET status=EXCLUDED.status,notes=EXCLUDED.notes RETURNING *",
    [int(req.body.student_id,"student_id"),str(req.body.attendance_date,"attendance_date",10),status,str(req.body.notes,"notes",1000,false)]);
  res.status(201).json(q.rows[0]);
}));
app.patch("/api/attendance/:id",dbRequired,admin,wrap(async(req,res)=>{
  const status=str(req.body.status,"status",20).toLowerCase();if(!["present","absent","late","leave"].includes(status))return fail(res,400,"Invalid attendance status.");
  const q=await pool.query("UPDATE attendance SET status=$1 WHERE id=$2 RETURNING *",[status,int(req.params.id,"id")]);if(!q.rowCount)return fail(res,404,"Attendance record not found.");res.json(q.rows[0]);
}));
app.delete("/api/attendance/:id",dbRequired,admin,wrap(async(req,res)=>{const q=await pool.query("DELETE FROM attendance WHERE id=$1 RETURNING id",[int(req.params.id,"id")]);if(!q.rowCount)return fail(res,404,"Attendance record not found.");res.json({deleted:true,id:q.rows[0].id});}));

app.get("/api/results",dbRequired,wrap(async(req,res)=>{
  const id=req.query.student_id?int(req.query.student_id,"student_id"):null;
  const q=await pool.query("SELECT r.*,s.name AS student_name,s.class FROM results r JOIN students s ON s.id=r.student_id "+(id?"WHERE r.student_id=$1 ":"")+"ORDER BY r.created_at DESC LIMIT 1000",id?[id]:[]);
  res.json(q.rows);
}));
app.post("/api/results",dbRequired,admin,wrap(async(req,res)=>{
  const marks=num(req.body.marks_obtained,"marks_obtained"),total=num(req.body.total_marks,"total_marks");
  if(total<=0||marks>total)return fail(res,400,"total_marks must be positive and marks cannot exceed total.");
  const q=await pool.query("INSERT INTO results(student_id,exam,subject,marks_obtained,total_marks,grade,remarks) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *",
    [int(req.body.student_id,"student_id"),str(req.body.exam,"exam",120),str(req.body.subject,"subject",120),marks,total,str(req.body.grade,"grade",10,false),str(req.body.remarks,"remarks",1000,false)]);
  res.status(201).json(q.rows[0]);
}));
app.patch("/api/results/:id",dbRequired,admin,wrap(async(req,res)=>{
  const marks=num(req.body.marks_obtained,"marks_obtained"),total=num(req.body.total_marks,"total_marks");
  if(total<=0||marks>total)return fail(res,400,"Invalid marks or total.");
  const q=await pool.query("UPDATE results SET marks_obtained=$1,total_marks=$2,grade=$3,remarks=$4 WHERE id=$5 RETURNING *",
    [marks,total,str(req.body.grade,"grade",10,false),str(req.body.remarks,"remarks",1000,false),int(req.params.id,"id")]);
  if(!q.rowCount)return fail(res,404,"Result record not found.");res.json(q.rows[0]);
}));
app.delete("/api/results/:id",dbRequired,admin,wrap(async(req,res)=>{const q=await pool.query("DELETE FROM results WHERE id=$1 RETURNING id",[int(req.params.id,"id")]);if(!q.rowCount)return fail(res,404,"Result record not found.");res.json({deleted:true,id:q.rows[0].id});}));

app.use(express.static(path.join(__dirname,"..","public")));
app.use((req,res)=>req.path.startsWith("/api/")?fail(res,404,"API route not found."):res.status(404).send("Page not found."));
app.use((err,_req,res,_next)=>{
  if(err?.message && /is required|characters or fewer|positive integer|non-negative number/.test(err.message))return fail(res,400,err.message);
  if(err?.code==="23503")return fail(res,400,"Referenced record does not exist.");
  if(err?.code==="23505")return fail(res,409,"A record with these details already exists.");
  if(err?.code==="22P02")return fail(res,400,"Invalid value format.");
  console.error("Request failed:",err?.message||"Unknown error");return fail(res,500,"Internal server error.");
});
module.exports = app;
