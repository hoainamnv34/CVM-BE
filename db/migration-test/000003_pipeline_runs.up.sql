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


ALTER TABLE "pipeline_runs" ADD FOREIGN KEY ("project_id") REFERENCES "projects" ("id");
