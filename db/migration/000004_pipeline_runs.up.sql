CREATE TABLE "pipeline_runs" (
  "id" SERIAL PRIMARY KEY,
  "branch_name" TEXT,
  "commit_hash" TEXT,
  "project_id" BIGINT,
  "status" BIGINT,
  "pipeline_run_url" TEXT,
  "pipeline_run_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);