CREATE TABLE "tests" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT,
  "pipeline_run_id" BIGINT,
  "tool_type_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE "tests" ADD FOREIGN KEY ("pipeline_run_id") REFERENCES "pipeline_runs" ("id");
ALTER TABLE "tests" ADD FOREIGN KEY ("tool_type_id") REFERENCES "tool_types" ("id");
