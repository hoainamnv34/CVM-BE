CREATE TABLE "users" (
  "id" SERIAL PRIMARY KEY,
  "username" TEXT,
  "password" TEXT,
  "full_name" TEXT,
  "email" TEXT,
  "updated_at" TIMESTAMPTZ DEFAULT NOW(),
  "created_at" TIMESTAMPTZ DEFAULT NOW()
);