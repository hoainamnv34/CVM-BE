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
