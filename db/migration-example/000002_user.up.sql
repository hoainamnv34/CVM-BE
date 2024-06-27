CREATE TABLE "users" (
  "username" varchar PRIMARY KEY,
  "hashed_password" varchar,
  "full_name" varchar,
  "email" varchar UNIQUE,
  "password_changed_at" timestamptz NULL DEFAULT('0001-01-01 00:00:00Z'),  
  "created_at" timestamptz NULL DEFAULT (now())
);

ALTER TABLE "accounts" ADD FOREIGN KEY ("owner") REFERENCES "users" ("username");

-- CREATE UNIQUE INDEX ON "accounts" ("owner", "currency");
ALTER TABLE "accounts" ADD CONSTRAINT "owner_currency_key" UNIQUE ("owner", "currency");