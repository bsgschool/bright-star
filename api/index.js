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

app.get("/api/students",dbRequired,admin,wrap(async(req,res)=>{
 const page=Math.max(1,Number.parseInt(req.query.page||"1",10)||1),limit=Math.min(100,Math.max(1,Number.parseInt(req.query.limit||"25",10)||25)),p=[],w=[];
 if(req.query.q){p.push("%"+str(req.query.q,"q",120)+"%");w.push(`(name ILIKE $${p.length} OR admission_no ILIKE $${p.length} OR father_name ILIKE $${p.length} OR roll_no ILIKE $${p.length})`)}
 if(req.query.class&&req.query.class!=="all"){p.push(str(req.query.class,"class",80));w.push(`class=$${p.length}`)}
 if(req.query.status&&req.query.status!=="all"){p.push(str(req.query.status,"status",20));w.push(`status=$${p.length}`)}
 const where=w.length?" WHERE "+w.join(" AND "):"",count=await pool.query("SELECT COUNT(*)::int AS total FROM students"+where,p),rows=await pool.query("SELECT id,admission_no,name,father_name,class,roll_no,section,admission_date,monthly_fee,status,contact,notes,created_at FROM students"+where+` ORDER BY name LIMIT $${p.length+1} OFFSET $${p.length+2}`,[...p,limit,(page-1)*limit]);res.json({items:rows.rows,total:count.rows[0].total,page,limit,pages:Math.ceil(count.rows[0].total/limit)});
}));
app.post("/api/students",dbRequired,admin,wrap(async(req,res)=>{
 const admission=str(req.body.admission_no,"admission_no",50),name=str(req.body.name,"name",160),klass=str(req.body.class,"class",80),roll=str(req.body.roll_no||admission,"roll_no",40),father=str(req.body.father_name,"father_name",160,false),contact=str(req.body.contact,"contact",40,false),monthly=num(req.body.monthly_fee??0,"monthly_fee"),status=str(req.body.status||"active","status",20);
 if(!["active","withdrawn","graduated"].includes(status))return fail(res,400,"Invalid student status.");
 const q=await pool.query("INSERT INTO students(admission_no,name,class,roll_no,father_name,contact,admission_date,monthly_fee,status,notes,section) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *",[admission,name,klass,roll,father,contact,req.body.admission_date||null,monthly,status,str(req.body.notes,"notes",1000,false),str(req.body.section,"section",30,false)]);res.status(201).json(q.rows[0]);
}));
app.get("/api/teachers",dbRequired,wrap(async(_req,res)=>res.json((await pool.query("SELECT id,name,subject,created_at FROM teachers ORDER BY name")).rows)));
app.post("/api/teachers",dbRequired,admin,wrap(async(req,res)=>{
  const q=await pool.query("INSERT INTO teachers(name,subject) VALUES($1,$2) RETURNING *",[str(req.body.name,"name",160),str(req.body.subject,"subject",120)]);res.status(201).json(q.rows[0]);
}));
app.get("/api/classes",dbRequired,wrap(async(_req,res)=>res.json((await pool.query("SELECT id,name,section,room,class_teacher,created_at FROM classes ORDER BY sort_order,name,section")).rows)));

// Fee records are sensitive: all fee-management endpoints require an authenticated admin.
app.get("/api/fees/summary",dbRequired,admin,wrap(async(_req,res)=>{
 const q=await pool.query(`SELECT COUNT(*)::int AS total_records,COALESCE(SUM(amount),0)::numeric(12,2) AS total_billed,COALESCE(SUM(amount_paid),0)::numeric(12,2) AS total_collected,COALESCE(SUM(GREATEST(amount-amount_paid,0)),0)::numeric(12,2) AS outstanding,COUNT(*) FILTER(WHERE amount_paid>=amount)::int AS paid_count,COUNT(*) FILTER(WHERE amount_paid>0 AND amount_paid<amount)::int AS partial_count,COUNT(*) FILTER(WHERE amount_paid=0)::int AS unpaid_count,COUNT(*) FILTER(WHERE amount_paid<amount AND due_date<CURRENT_DATE)::int AS overdue_count FROM fees`);res.json(q.rows[0]);
}));
app.get("/api/fees",dbRequired,admin,wrap(async(req,res)=>{
 const p=[],w=[];
 if(req.query.student_id){p.push(int(req.query.student_id,"student_id"));w.push(`f.student_id=$${p.length}`)}
 if(req.query.month){p.push(str(req.query.month,"month",20));w.push(`f.month=$${p.length}`)}
 if(req.query.q){p.push("%"+str(req.query.q,"q",100)+"%");w.push(`(s.name ILIKE $${p.length} OR s.roll_no ILIKE $${p.length} OR f.invoice_no ILIKE $${p.length})`)}
 const st=req.query.status;
 if(st&&st!=="all"){if(st==="paid")w.push("f.amount_paid>=f.amount");else if(st==="partial")w.push("f.amount_paid>0 AND f.amount_paid<f.amount");else if(st==="unpaid")w.push("f.amount_paid=0");else if(st==="overdue")w.push("f.amount_paid<f.amount AND f.due_date<CURRENT_DATE");else return fail(res,400,"Invalid fee filter.")}
 const q=await pool.query(`SELECT f.*,s.name AS student_name,s.class AS student_class,s.roll_no,s.father_name,s.contact,GREATEST(f.amount-f.amount_paid,0)::numeric(12,2) AS balance,CASE WHEN f.amount_paid>=f.amount THEN 'paid' WHEN f.amount_paid>0 THEN 'partial' ELSE 'unpaid' END AS payment_status FROM fees f JOIN students s ON s.id=f.student_id ${w.length?'WHERE '+w.join(' AND '):''} ORDER BY f.due_date ASC,f.created_at DESC LIMIT 1000`,p);res.json(q.rows);
}));
app.post("/api/fees",dbRequired,admin,wrap(async(req,res)=>{
 const amount=num(req.body.amount,"amount"),paid=req.body.amount_paid==null?0:num(req.body.amount_paid,"amount_paid");if(paid>amount)return fail(res,400,"amount_paid cannot exceed amount.");
 const q=await pool.query(`INSERT INTO fees(student_id,amount,month,status,paid_at,notes,amount_paid,due_date,invoice_no) VALUES($1,$2,$3,CASE WHEN $4>0 THEN 'partial' ELSE 'unpaid' END,CASE WHEN $4 >= $2 THEN NOW() ELSE NULL END,$5,$4,$6,COALESCE(NULLIF($7,''),'BSG-'||to_char(NOW(),'YYMM')||'-'||lpad(nextval('fee_invoice_seq')::text,6,'0'))) RETURNING *,GREATEST(amount-amount_paid,0)::numeric(12,2) AS balance`,[int(req.body.student_id,"student_id"),amount,str(req.body.month,"month",20),paid,str(req.body.notes,"notes",1000,false),req.body.due_date?str(req.body.due_date,"due_date",10):null,str(req.body.invoice_no||"","invoice_no",60)]);res.status(201).json(q.rows[0]);
}));
app.patch("/api/fees/:id",dbRequired,admin,wrap(async(req,res)=>{
 const id=int(req.params.id,"id"),old=await pool.query("SELECT * FROM fees WHERE id=$1",[id]);if(!old.rowCount)return fail(res,404,"Fee record not found.");const f=old.rows[0],amount=req.body.amount==null?Number(f.amount):num(req.body.amount,"amount"),paid=req.body.amount_paid==null?Number(f.amount_paid||0):num(req.body.amount_paid,"amount_paid");if(paid>amount)return fail(res,400,"amount_paid cannot exceed amount.");
 const q=await pool.query(`UPDATE fees SET amount=$1,amount_paid=$2,month=$3,due_date=$4,notes=$5,status=CASE WHEN $2 >= $1 THEN 'paid' WHEN $2>0 THEN 'partial' ELSE 'unpaid' END,paid_at=CASE WHEN $2 >= $1 THEN COALESCE(paid_at,NOW()) ELSE NULL END WHERE id=$6 RETURNING *,GREATEST(amount-amount_paid,0)::numeric(12,2) AS balance`,[amount,paid,req.body.month==null?f.month:str(req.body.month,"month",20),req.body.due_date===undefined?f.due_date:req.body.due_date,req.body.notes===undefined?f.notes:str(req.body.notes,"notes",1000,false),id]);res.json(q.rows[0]);
}));
app.post("/api/fees/:id/payment",dbRequired,admin,wrap(async(req,res)=>{
 const id=int(req.params.id,"id"),payment=num(req.body.amount,"amount");if(payment<=0)return fail(res,400,"Payment amount must be greater than zero.");const client=await pool.connect();try{await client.query("BEGIN");const old=await client.query("SELECT * FROM fees WHERE id=$1 FOR UPDATE",[id]);if(!old.rowCount){await client.query("ROLLBACK");return fail(res,404,"Fee record not found.");}const f=old.rows[0],due=Number(f.amount)-Number(f.amount_paid||0);if(payment>due){await client.query("ROLLBACK");return fail(res,400,"Payment exceeds the remaining balance.");}const paid=Number(f.amount_paid||0)+payment;const q=await client.query(`UPDATE fees SET amount_paid=$1,status=CASE WHEN $1>=amount THEN 'paid' WHEN $1>0 THEN 'partial' ELSE 'unpaid' END,paid_at=CASE WHEN $1>=amount THEN NOW() ELSE paid_at END WHERE id=$2 RETURNING *,GREATEST(amount-amount_paid,0)::numeric(12,2) AS balance`,[paid,id]);await client.query("INSERT INTO fee_payments(fee_id,amount,payment_method,reference,received_by) VALUES($1,$2,$3,$4,$5)",[id,payment,str(req.body.payment_method||"cash","payment_method",30),str(req.body.reference,"reference",100,false),req.authUser.sub]);await client.query("COMMIT");res.status(201).json({fee:q.rows[0],payment:{amount:payment,payment_method:req.body.payment_method||"cash",reference:req.body.reference||null,paid_at:new Date().toISOString()}});}catch(e){await client.query("ROLLBACK");throw e;}finally{client.release()}
}));
app.get("/api/fees/:id/payments",dbRequired,admin,wrap(async(req,res)=>{const q=await pool.query("SELECT p.* FROM fee_payments p WHERE p.fee_id=$1 ORDER BY p.paid_at DESC",[int(req.params.id,"id")]);res.json(q.rows)}));
app.delete("/api/fees/:id",dbRequired,admin,wrap(async(req,res)=>{const q=await pool.query("DELETE FROM fees WHERE id=$1 RETURNING id",[int(req.params.id,"id")]);if(!q.rowCount)return fail(res,404,"Fee record not found.");res.json({deleted:true,id:q.rows[0].id})}));

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


// Full academic-year fee ledger. Each payment is immutable and gets its own reprintable receipt.
app.get("/api/academic-years",dbRequired,admin,wrap(async(_req,res)=>res.json((await pool.query("SELECT * FROM academic_years ORDER BY start_date DESC NULLS LAST,name DESC")).rows)));
app.post("/api/academic-years",dbRequired,admin,wrap(async(req,res)=>{
 const name=str(req.body.name,"name",20);if(!/^\d{4}-\d{2,4}$/.test(name))return fail(res,400,"Academic year must look like 2026-27.");
 const client=await pool.connect();try{await client.query("BEGIN");if(req.body.is_current)await client.query("UPDATE academic_years SET is_current=FALSE");const q=await client.query("INSERT INTO academic_years(name,start_date,end_date,is_current) VALUES($1,$2,$3,$4) ON CONFLICT(name) DO UPDATE SET start_date=COALESCE(EXCLUDED.start_date,academic_years.start_date),end_date=COALESCE(EXCLUDED.end_date,academic_years.end_date),is_current=EXCLUDED.is_current RETURNING *",[name,req.body.start_date||null,req.body.end_date||null,Boolean(req.body.is_current)]);await client.query("COMMIT");res.status(201).json(q.rows[0]);}catch(e){await client.query("ROLLBACK");throw e;}finally{client.release()}
}));
app.post("/api/fee-records/generate",dbRequired,admin,wrap(async(req,res)=>{
 const year=str(req.body.academic_year,"academic_year",20),month=req.body.month==null?null:int(req.body.month,"month"),studentId=req.body.student_id?int(req.body.student_id,"student_id"):null;
 const y=await pool.query("SELECT name FROM academic_years WHERE name=$1",[year]);if(!y.rowCount)return fail(res,400,"Create this academic year first.");if(month&&month>12)return fail(res,400,"month must be between 1 and 12.");
 const months=month?[month]:Array.from({length:12},(_,i)=>i+1),client=await pool.connect();let made=0;try{await client.query("BEGIN");const students=await client.query("SELECT id,monthly_fee FROM students WHERE status='active' AND ($1::bigint IS NULL OR id=$1)",[studentId]);for(const st of students.rows){for(const m of months){const r=await client.query(`INSERT INTO fee_records(student_id,academic_year,month,fee_due,paid_amount,discount,fine,balance,status) VALUES($1,$2,$3,$4,0,0,0,$4,'unpaid') ON CONFLICT(student_id,academic_year,month) DO NOTHING`,[st.id,year,m,Number(st.monthly_fee||0)]);made+=r.rowCount}}await client.query("INSERT INTO audit_log(action,details) VALUES($1,$2::jsonb)",["generate_fee_schedule",JSON.stringify({academic_year:year,month,student_id:studentId,created:made})]);await client.query("COMMIT");res.status(201).json({created:made,academic_year:year,months:months.length,students:students.rowCount});}catch(e){await client.query("ROLLBACK");throw e;}finally{client.release()}
}));
app.get("/api/fee-records",dbRequired,admin,wrap(async(req,res)=>{
 const p=[],w=[];for(const [key,col] of [["student_id","fr.student_id"],["academic_year","fr.academic_year"],["month","fr.month"]])if(req.query[key]){p.push(key==="month"?int(req.query[key],key):key==="student_id"?int(req.query[key],key):str(req.query[key],key,20));w.push(`${col}=$${p.length}`)}
 if(req.query.q){p.push("%"+str(req.query.q,"q",120)+"%");w.push(`(s.name ILIKE $${p.length} OR s.admission_no ILIKE $${p.length} OR s.father_name ILIKE $${p.length})`)}
 if(req.query.status&&req.query.status!=="all"){p.push(str(req.query.status,"status",10));w.push(`fr.status=$${p.length}`)}
 const q=await pool.query(`SELECT fr.*,s.admission_no,s.name AS student_name,s.father_name,s.class AS student_class,s.roll_no,s.section,s.monthly_fee, GREATEST(fr.fee_due-fr.discount+fr.fine-fr.paid_amount,0)::numeric(12,2) AS balance FROM fee_records fr JOIN students s ON s.id=fr.student_id ${w.length?"WHERE "+w.join(" AND "):""} ORDER BY s.name,fr.academic_year,fr.month LIMIT 5000`,p);res.json(q.rows);
}));
app.patch("/api/fee-records/:id",dbRequired,admin,wrap(async(req,res)=>{const id=int(req.params.id,"id"),old=await pool.query("SELECT * FROM fee_records WHERE id=$1",[id]);if(!old.rowCount)return fail(res,404,"Fee record not found.");const f=old.rows[0],discount=req.body.discount==null?Number(f.discount):num(req.body.discount,"discount"),fine=req.body.fine==null?Number(f.fine):num(req.body.fine,"fine"),total=Number(f.fee_due)-discount+fine;if(discount>Number(f.fee_due))return fail(res,400,"Discount cannot exceed fee due.");if(Number(f.paid_amount)>total)return fail(res,400,"Adjustment would make paid amount exceed the new total.");const balance=Number((total-Number(f.paid_amount)).toFixed(2)),q=await pool.query("UPDATE fee_records SET discount=$1,fine=$2,balance=$3,status=CASE WHEN $3<=0 THEN 'paid' WHEN paid_amount>0 THEN 'partial' ELSE 'unpaid' END,notes=COALESCE($4,notes),updated_at=NOW() WHERE id=$5 RETURNING *",[discount,fine,balance,req.body.notes==null?null:str(req.body.notes,"notes",1000,false),id]);await pool.query("INSERT INTO audit_log(action,student_id,details) VALUES($1,$2,$3::jsonb)",["fee_adjustment",f.student_id,JSON.stringify({fee_record_id:id,discount,fine,balance})]);res.json(q.rows[0])}));
app.post("/api/fee-records/payment",dbRequired,admin,wrap(async(req,res)=>{
 const id=int(req.body.fee_record_id,"fee_record_id"),amount=num(req.body.amount,"amount");if(amount<=0)return fail(res,400,"Payment must be greater than zero.");const method=str(req.body.payment_method||"cash","payment_method",30),reference=str(req.body.reference,"reference",100,false),client=await pool.connect();
 try{await client.query("BEGIN");const old=await client.query("SELECT fr.*,s.name AS student_name,s.admission_no,s.class AS student_class,s.roll_no,s.father_name FROM fee_records fr JOIN students s ON s.id=fr.student_id WHERE fr.id=$1 FOR UPDATE OF fr",[id]);if(!old.rowCount){await client.query("ROLLBACK");return fail(res,404,"Fee record not found.");}const f=old.rows[0],total=Number(f.fee_due)-Number(f.discount)+Number(f.fine),previous=Math.max(total-Number(f.paid_amount),0);if(amount>previous){await client.query("ROLLBACK");return fail(res,400,"Payment exceeds remaining balance.");}const remaining=Number((previous-amount).toFixed(2)),paid=Number((Number(f.paid_amount)+amount).toFixed(2)),receipt="BSG-"+new Date().getFullYear()+"-"+String(await nextReceipt(client)).padStart(4,"0");const pay=await client.query("INSERT INTO fee_record_payments(fee_record_id,amount,receipt_no,payment_method,reference,previous_balance,remaining_balance,received_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",[id,amount,receipt,method,reference,previous,remaining,req.authUser.sub]);const updated=await client.query("UPDATE fee_records SET paid_amount=$1,balance=$2,status=CASE WHEN $2<=0 THEN 'paid' WHEN $1>0 THEN 'partial' ELSE 'unpaid' END,payment_date=NOW(),receipt_no=$3,updated_at=NOW() WHERE id=$4 RETURNING *",[paid,remaining,receipt,id]);await client.query("INSERT INTO audit_log(action,student_id,details) VALUES($1,$2,$3::jsonb)",["fee_payment",f.student_id,JSON.stringify({fee_record_id:id,amount,receipt_no:receipt,previous_balance:previous,remaining_balance:remaining})]);await client.query("COMMIT");res.status(201).json({payment:pay,fee:updated,student:{name:f.student_name,admission_no:f.admission_no,class:f.student_class,roll_no:f.roll_no,father_name:f.father_name}});}catch(e){await client.query("ROLLBACK");throw e;}finally{client.release()}
}));
async function nextReceipt(client){const q=await client.query("SELECT nextval('bsg_receipt_seq') AS n");return Number(q.rows[0].n)}
app.get("/api/fee-records/:id/payments",dbRequired,admin,wrap(async(req,res)=>{const q=await pool.query("SELECT p.*,fr.academic_year,fr.month,fr.student_id,s.name AS student_name,s.admission_no,s.class AS student_class,s.roll_no FROM fee_record_payments p JOIN fee_records fr ON fr.id=p.fee_record_id JOIN students s ON s.id=fr.student_id WHERE fr.id=$1 ORDER BY p.paid_at DESC",[int(req.params.id,"id")]);res.json(q.rows)}));
app.get("/api/receipts/:receiptNo",dbRequired,admin,wrap(async(req,res)=>{const q=await pool.query("SELECT p.*,fr.academic_year,fr.month,fr.fee_due,fr.discount,fr.fine,s.name AS student_name,s.admission_no,s.father_name,s.class AS student_class,s.roll_no,s.section FROM fee_record_payments p JOIN fee_records fr ON fr.id=p.fee_record_id JOIN students s ON s.id=fr.student_id WHERE p.receipt_no=$1",[str(req.params.receiptNo,"receiptNo",50)]);if(!q.rowCount)return fail(res,404,"Receipt not found.");res.json(q.rows[0])}));
app.get("/api/reports/summary",dbRequired,admin,wrap(async(req,res)=>{const year=req.query.academic_year?str(req.query.academic_year,"academic_year",20):null;const p=year?[year]:[];const where=year?" WHERE academic_year=$1":"";const [students,fees,payments,classes]=await Promise.all([pool.query("SELECT COUNT(*)::int AS active_students FROM students WHERE status='active'"),pool.query(`SELECT COALESCE(SUM(fee_due-discount+fine),0)::numeric(14,2) AS assessed,COALESCE(SUM(paid_amount),0)::numeric(14,2) AS collected,COALESCE(SUM(balance),0)::numeric(14,2) AS outstanding,COUNT(*) FILTER(WHERE status='paid')::int AS paid_count,COUNT(*) FILTER(WHERE status='partial')::int AS partial_count,COUNT(*) FILTER(WHERE status='unpaid')::int AS unpaid_count FROM fee_records${where}`,p),pool.query(`SELECT COALESCE(SUM(amount),0)::numeric(14,2) AS collected_today FROM fee_record_payments WHERE paid_at::date=CURRENT_DATE${year?" AND fee_record_id IN (SELECT id FROM fee_records WHERE academic_year=$1)":""}`,p),pool.query(`SELECT s.class,COALESCE(SUM(fr.fee_due-fr.discount+fr.fine),0)::numeric(14,2) AS assessed,COALESCE(SUM(fr.paid_amount),0)::numeric(14,2) AS collected,COALESCE(SUM(fr.balance),0)::numeric(14,2) AS outstanding FROM fee_records fr JOIN students s ON s.id=fr.student_id${where?" WHERE fr.academic_year=$1":""} GROUP BY s.class ORDER BY s.class`,p)]);res.json({active_students:students.rows[0].active_students,...fees.rows[0],collected_today:payments.rows[0].collected_today,class_wise:classes.rows})}));
app.get("/api/reports/collections",dbRequired,admin,wrap(async(req,res)=>{const group=str(req.query.group||"month","group",10);if(!["day","month","year"].includes(group))return fail(res,400,"group must be day, month, or year.");const p=[],w=[];if(req.query.academic_year){p.push(str(req.query.academic_year,"academic_year",20));w.push(`fr.academic_year=$${p.length}`)}const q=await pool.query(`SELECT date_trunc($${p.length+1},p.paid_at) AS period,COUNT(*)::int AS payments,COALESCE(SUM(p.amount),0)::numeric(14,2) AS collected FROM fee_record_payments p JOIN fee_records fr ON fr.id=p.fee_record_id ${w.length?"WHERE "+w.join(" AND "):""} GROUP BY date_trunc($${p.length+1},p.paid_at) ORDER BY period DESC LIMIT 120`,[...p,group]);res.json(q.rows)}));
app.get("/api/reports/payments.csv",dbRequired,admin,wrap(async(req,res)=>{const p=[],w=[];if(req.query.academic_year){p.push(str(req.query.academic_year,"academic_year",20));w.push(`fr.academic_year=$${p.length}`)}if(req.query.from){p.push(str(req.query.from,"from",10));w.push(`p.paid_at >= $${p.length}::date`)}if(req.query.to){p.push(str(req.query.to,"to",10));w.push(`p.paid_at < ($${p.length}::date + INTERVAL '1 day')`)}const q=await pool.query(`SELECT p.receipt_no,p.paid_at,s.admission_no,s.name,s.father_name,s.class,fr.academic_year,fr.month,p.amount,p.payment_method,p.reference,p.previous_balance,p.remaining_balance FROM fee_record_payments p JOIN fee_records fr ON fr.id=p.fee_record_id JOIN students s ON s.id=fr.student_id ${w.length?"WHERE "+w.join(" AND "):""} ORDER BY p.paid_at DESC LIMIT 20000`,p);const keys=["receipt_no","paid_at","admission_no","name","father_name","class","academic_year","month","amount","payment_method","reference","previous_balance","remaining_balance"],csv=[keys.join(","),...q.rows.map(r=>keys.map(k=>'"'+String(r[k]??"").replace(/"/g,'""')+'"').join(","))].join("\r\n");res.setHeader("Content-Type","text/csv; charset=utf-8");res.setHeader("Content-Disposition","attachment; filename=bright-star-fee-report.csv");res.send(csv)}));
app.post("/api/students/promote",dbRequired,admin,wrap(async(req,res)=>{const from=str(req.body.from_class,"from_class",80),to=str(req.body.to_class,"to_class",80),year=str(req.body.academic_year,"academic_year",20);const y=await pool.query("SELECT 1 FROM academic_years WHERE name=$1",[year]);if(!y.rowCount)return fail(res,400,"Create the destination academic year first.");const q=await pool.query("UPDATE students SET class=$1 WHERE class=$2 AND status='active' RETURNING id",[to,from]);await pool.query("INSERT INTO audit_log(action,details) VALUES($1,$2::jsonb)",["class_promotion",JSON.stringify({from_class:from,to_class:to,academic_year:year,students_promoted:q.rowCount})]);res.json({promoted:q.rowCount,from_class:from,to_class:to,academic_year:year,note:"Historical fee records are preserved."})}));

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
