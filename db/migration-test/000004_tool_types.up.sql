CREATE TABLE "tool_types" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT,
  "description" TEXT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);