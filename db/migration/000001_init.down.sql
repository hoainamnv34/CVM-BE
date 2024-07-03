ALTER TABLE "finding_tests" DROP CONSTRAINT fk_test;
ALTER TABLE "finding_tests" DROP CONSTRAINT fk_finding;
DROP TABLE IF EXISTS "finding_tests";

ALTER TABLE "findings" DROP CONSTRAINT fk_project_finding;
DROP TABLE IF EXISTS "findings";

ALTER TABLE "tests" DROP CONSTRAINT fk_tool_type;
ALTER TABLE "tests" DROP CONSTRAINT fk_pipeline_run;
DROP TABLE IF EXISTS "tests";

DROP TABLE IF EXISTS "tool_types";

ALTER TABLE "pipeline_runs" DROP CONSTRAINT fk_project;
DROP TABLE IF EXISTS "pipeline_runs";

ALTER TABLE "projects" DROP CONSTRAINT fk_pipeline_evaluation;
ALTER TABLE "projects" DROP CONSTRAINT fk_project_group;
DROP TABLE IF EXISTS "projects";

DROP TABLE IF EXISTS "pipeline_evaluations";

DROP TABLE IF EXISTS "project_groups";