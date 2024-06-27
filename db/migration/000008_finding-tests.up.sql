CREATE TABLE "finding_tests" (
  "id" SERIAL PRIMARY KEY,
  "test_id" BIGINT,
  "finding_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);