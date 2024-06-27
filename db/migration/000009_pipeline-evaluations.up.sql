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