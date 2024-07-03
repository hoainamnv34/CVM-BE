CREATE TABLE "finding_tests" (
  "id" SERIAL PRIMARY KEY,
  "test_id" BIGINT,
  "finding_id" BIGINT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE "finding_tests" ADD FOREIGN KEY ("finding_id") REFERENCES "findings" ("id");
ALTER TABLE "finding_tests" ADD FOREIGN KEY ("test_id") REFERENCES "tests" ("id");
