CREATE TABLE "findings" (
  "id" SERIAL PRIMARY KEY,
  "project_id" BIGINT,
  "title" TEXT,
  "risk_description" TEXT,
  "test_description" TEXT,
  "severity" BIGINT,
  "cwe" BIGINT,
  "line" BIGINT,
  "file_path" TEXT,
  "vuln_id_from_tool" TEXT,
  "unique_id_from_tool" TEXT,
  "mitigation" TEXT,
  "impact" TEXT,
  "reference" TEXT,
  "reviewer" BIGINT,
  "active" BOOLEAN,
  "dynamic_finding" BOOLEAN,
  "verified" BOOLEAN,
  "false_p" BOOLEAN,
  "duplicate" BOOLEAN,
  "risk_accepted" BOOLEAN,
  "static_finding" BOOLEAN,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);