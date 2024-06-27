CREATE TABLE "tests" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT,
  "pipeline_run_id" BIGINT,
  "tool_type_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);