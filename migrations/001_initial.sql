BEGIN;
CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS classes (
 id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, section TEXT, room TEXT, class_teacher TEXT,
 sort_order INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(name,section)
);
CREATE TABLE IF NOT EXISTS students (
 id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, class TEXT NOT NULL, roll_no TEXT NOT NULL,
 father_name TEXT, contact TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(class,roll_no)
);
CREATE TABLE IF NOT EXISTS teachers (
 id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, subject TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS fees (
 id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
 amount NUMERIC(12,2) NOT NULL CHECK(amount>=0), month TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'unpaid' CHECK(status IN ('paid','unpaid','partial','waived')),
 paid_at TIMESTAMPTZ, notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(student_id,month)
);
CREATE TABLE IF NOT EXISTS attendance (
 id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
 attendance_date DATE NOT NULL, status TEXT NOT NULL CHECK(status IN ('present','absent','late','leave')),
 notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(student_id,attendance_date)
);
CREATE TABLE IF NOT EXISTS results (
 id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
 exam TEXT NOT NULL, subject TEXT NOT NULL, marks_obtained NUMERIC(8,2) NOT NULL CHECK(marks_obtained>=0),
 total_marks NUMERIC(8,2) NOT NULL CHECK(total_marks>0), grade TEXT, remarks TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK(marks_obtained<=total_marks)
);
CREATE INDEX IF NOT EXISTS idx_students_class ON students(class);
CREATE INDEX IF NOT EXISTS idx_fees_student_month ON fees(student_id,month);
CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(attendance_date);
CREATE INDEX IF NOT EXISTS idx_results_student_exam ON results(student_id,exam);
COMMIT;
