-- Drop tables if they already exist to avoid conflicts
DROP TABLE IF EXISTS "finding_tests" CASCADE;
DROP TABLE IF EXISTS "findings" CASCADE;
DROP TABLE IF EXISTS "tests" CASCADE;
DROP TABLE IF EXISTS "tool_types" CASCADE;
DROP TABLE IF EXISTS "pipeline_runs" CASCADE;
DROP TABLE IF EXISTS "projects" CASCADE;
DROP TABLE IF EXISTS "pipeline_evaluations" CASCADE;
DROP TABLE IF EXISTS "project_groups" CASCADE;

CREATE TABLE "project_groups" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT,
  "description" TEXT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE "pipeline_evaluations" (
  "id" SERIAL PRIMARY KEY,
  "severity_critical_score" BIGINT,
  "severity_high_score" BIGINT,
  "severity_medium_score" BIGINT,
  "severity_low_score" BIGINT,
  "threshold_score" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE "projects" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT,
  "description" TEXT,
  "project_group_id" BIGINT,
  "repository_url" TEXT,
  "pipeline_evaluation_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE "projects" 
  ADD CONSTRAINT fk_project_group 
  FOREIGN KEY ("project_group_id") 
  REFERENCES "project_groups" ("id");

ALTER TABLE "projects" 
  ADD CONSTRAINT fk_pipeline_evaluation 
  FOREIGN KEY ("pipeline_evaluation_id") 
  REFERENCES "pipeline_evaluations" ("id");

CREATE TABLE "pipeline_runs" (
  "id" SERIAL PRIMARY KEY,
  "branch_name" TEXT,
  "commit_hash" TEXT,
  "project_id" BIGINT,
  "status" BIGINT,
  "run_url" TEXT,
  "run_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE "pipeline_runs" 
  ADD CONSTRAINT fk_project 
  FOREIGN KEY ("project_id") 
  REFERENCES "projects" ("id");

CREATE TABLE "tool_types" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT,
  "description" TEXT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE "tests" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT,
  "pipeline_run_id" BIGINT,
  "tool_type_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE "tests" 
  ADD CONSTRAINT fk_pipeline_run 
  FOREIGN KEY ("pipeline_run_id") 
  REFERENCES "pipeline_runs" ("id");

ALTER TABLE "tests" 
  ADD CONSTRAINT fk_tool_type 
  FOREIGN KEY ("tool_type_id") 
  REFERENCES "tool_types" ("id");

CREATE TABLE "findings" (
  "id" SERIAL PRIMARY KEY,
  "project_id" BIGINT,
  "title" TEXT,
  "description" TEXT,
  "severity" BIGINT,
  "cwe" BIGINT,
  "line" BIGINT,
  "file_path" TEXT,
  "vuln_id_from_tool" TEXT,
  "mitigation" TEXT,
  "reference" TEXT,
  "active" BOOLEAN,
  "dynamic_finding" BOOLEAN,
  "duplicate" BOOLEAN,
  "risk_accepted" BOOLEAN,
  "static_finding" BOOLEAN,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE "findings" 
  ADD CONSTRAINT fk_project_finding 
  FOREIGN KEY ("project_id") 
  REFERENCES "projects" ("id");

CREATE TABLE "finding_tests" (
  "id" SERIAL PRIMARY KEY,
  "test_id" BIGINT,
  "finding_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE "finding_tests" 
  ADD CONSTRAINT fk_finding 
  FOREIGN KEY ("finding_id") 
  REFERENCES "findings" ("id");

ALTER TABLE "finding_tests" 
  ADD CONSTRAINT fk_test 
  FOREIGN KEY ("test_id") 
  REFERENCES "tests" ("id");
