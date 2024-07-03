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

ALTER TABLE "findings" ADD FOREIGN KEY ("project_id") REFERENCES "projects" ("id");
