BEGIN;
ALTER TABLE students ADD COLUMN IF NOT EXISTS admission_no TEXT;
ALTER TABLE students ADD COLUMN IF NOT EXISTS admission_date DATE;
ALTER TABLE students ADD COLUMN IF NOT EXISTS section TEXT;
ALTER TABLE students ADD COLUMN IF NOT EXISTS monthly_fee NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(monthly_fee>=0);
ALTER TABLE students ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE students ADD COLUMN IF NOT EXISTS notes TEXT;
UPDATE students SET admission_no='BSG-'||LPAD(id::text,6,'0') WHERE admission_no IS NULL OR BTRIM(admission_no)='';
ALTER TABLE students ALTER COLUMN admission_no SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_students_admission_no_unique ON students(admission_no);
CREATE INDEX IF NOT EXISTS idx_students_name_admission ON students(name,admission_no);
CREATE TABLE IF NOT EXISTS academic_years (
 id BIGSERIAL PRIMARY KEY, name VARCHAR(20) NOT NULL UNIQUE,
 start_date DATE, end_date DATE, is_current BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO academic_years(name,is_current) VALUES('2026-27',TRUE) ON CONFLICT(name) DO NOTHING;
CREATE TABLE IF NOT EXISTS fee_records (
 id BIGSERIAL PRIMARY KEY,
 student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE RESTRICT,
 academic_year VARCHAR(20) NOT NULL REFERENCES academic_years(name) ON UPDATE CASCADE,
 month SMALLINT NOT NULL CHECK(month BETWEEN 1 AND 12),
 fee_due NUMERIC(12,2) NOT NULL CHECK(fee_due>=0),
 paid_amount NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(paid_amount>=0),
 discount NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(discount>=0),
 fine NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(fine>=0),
 balance NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(balance>=0),
 status VARCHAR(10) NOT NULL DEFAULT 'unpaid' CHECK(status IN ('paid','unpaid','partial')),
 payment_date TIMESTAMPTZ,
 receipt_no TEXT,
 notes TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(student_id,academic_year,month),
 CHECK(paid_amount<=fee_due-discount+fine)
);
CREATE INDEX IF NOT EXISTS idx_fee_records_year_month ON fee_records(academic_year,month);
CREATE INDEX IF NOT EXISTS idx_fee_records_student ON fee_records(student_id,academic_year);
CREATE TABLE IF NOT EXISTS fee_record_payments (
 id BIGSERIAL PRIMARY KEY,
 fee_record_id BIGINT NOT NULL REFERENCES fee_records(id) ON DELETE RESTRICT,
 amount NUMERIC(12,2) NOT NULL CHECK(amount>0),
 receipt_no TEXT NOT NULL UNIQUE,
 payment_method VARCHAR(30) NOT NULL DEFAULT 'cash',
 reference TEXT,
 previous_balance NUMERIC(12,2) NOT NULL,
 remaining_balance NUMERIC(12,2) NOT NULL,
 received_by TEXT,
 paid_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE SEQUENCE IF NOT EXISTS bsg_receipt_seq;
CREATE TABLE IF NOT EXISTS audit_log (
 id BIGSERIAL PRIMARY KEY, action TEXT NOT NULL,
 student_id BIGINT REFERENCES students(id) ON DELETE SET NULL,
 details JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
COMMIT;
