-- Insert sample data into project_groups
INSERT INTO "project_groups" ("name", "description") VALUES
('Project Group 1', 'Description for Project Group 1'),
('Project Group 2', 'Description for Project Group 2'),
('Project Group 3', 'Description for Project Group 3'),
('Project Group 4', 'Description for Project Group 4');

-- Insert sample data into pipeline_evaluations
INSERT INTO "pipeline_evaluations" ("severity_critical_score", "severity_high_score", "severity_medium_score", "severity_low_score", "threshold_score") VALUES
(100, 75, 50, 25, 200),
(120, 80, 60, 30, 250),
(150, 90, 70, 40, 300),
(130, 85, 65, 35, 280);

-- Insert sample data into projects
INSERT INTO "projects" ("name", "description", "project_group_id", "repository_url", "pipeline_evaluation_id") VALUES
('Project 1', 'Description for Project 1', 1, 'https://github.com/example/project1', 1),
('Project 2', 'Description for Project 2', 2, 'https://github.com/example/project2', 2),
('Project 3', 'Description for Project 3', 3, 'https://github.com/example/project3', 3),
('Project 4', 'Description for Project 4', 4, 'https://github.com/example/project4', 4),
('Project 5', 'Description for Project 5', 1, 'https://github.com/example/project5', 2);

-- Insert sample data into pipeline_runs
INSERT INTO "pipeline_runs" ("branch_name", "commit_hash", "project_id", "status", "run_url", "run_id") VALUES
('main', 'abcd1234', 1, 1, 'https://ci.example.com/run1', 101),
('develop', 'efgh5678', 2, 2, 'https://ci.example.com/run2', 102),
('feature1', 'ijkl9012', 3, 1, 'https://ci.example.com/run3', 103),
('feature2', 'mnop3456', 4, 3, 'https://ci.example.com/run4', 104),
('hotfix', 'qrst7890', 5, 1, 'https://ci.example.com/run5', 105);

-- Insert sample data into tool_types
INSERT INTO "tool_types" ("name", "description") VALUES
('Gitleaks', 'Description for Tool Type 1'),
('Checkov', 'Description for Tool Type 2'),
('DependencyCheck', 'Description for Tool Type 3'),
('Trivy', 'Description for Tool Type 4'),
('Zap', 'Description for Tool Type 5'),
('SonarQube', 'Description for Tool Type 6');

-- Insert sample data into tests
INSERT INTO "tests" ("name", "pipeline_run_id", "tool_type_id") VALUES
('Test 1', 1, 1),
('Test 2', 2, 2),
('Test 3', 3, 3),
('Test 4', 4, 4),
('Test 5', 5, 1);

-- Insert sample data into findings
INSERT INTO "findings" ("project_id", "title", "description", "severity", "cwe", "line", "file_path", "vuln_id_from_tool", "mitigation", "reference", "active", "dynamic_finding", "duplicate", "risk_accepted", "static_finding") VALUES
(1, 'Finding 1', 'Description for Finding 1', 1, 79, 10, '/path/to/file1', 'VULN-001', 'Mitigation for Finding 1', 'Reference for Finding 1', true, false, false, false, true),
(2, 'Finding 2', 'Description for Finding 2', 2, 89, 20, '/path/to/file2', 'VULN-002', 'Mitigation for Finding 2', 'Reference for Finding 2', false, true, true, true, false),
(3, 'Finding 3', 'Description for Finding 3', 3, 99, 30, '/path/to/file3', 'VULN-003', 'Mitigation for Finding 3', 'Reference for Finding 3', true, true, false, true, false),
(4, 'Finding 4', 'Description for Finding 4', 4, 109, 40, '/path/to/file4', 'VULN-004', 'Mitigation for Finding 4', 'Reference for Finding 4', false, false, true, false, true),
(5, 'Finding 5', 'Description for Finding 5', 5, 119, 50, '/path/to/file5', 'VULN-005', 'Mitigation for Finding 5', 'Reference for Finding 5', true, true, true, false, true);

-- Insert sample data into finding_tests
INSERT INTO "finding_tests" ("test_id", "finding_id") VALUES
(1, 1),
(2, 2),
(3, 3),
(4, 4),
(5, 5);
