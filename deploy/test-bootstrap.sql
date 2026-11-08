-- Test-only cluster bootstrap. Passwords come from this psql child's environment.
-- Production provisioning must establish these role/schema privileges separately.
\getenv migration_password CHEESETRAP_TEST_MIGRATION_PASSWORD
\getenv api_password CHEESETRAP_TEST_API_PASSWORD
\getenv collector_password CHEESETRAP_TEST_COLLECTOR_PASSWORD
\getenv worker_password CHEESETRAP_TEST_WORKER_PASSWORD
CREATE ROLE cheesetrap_migration LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'migration_password';
CREATE ROLE cheesetrap_api LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'api_password';
CREATE ROLE cheesetrap_collector LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'collector_password';
CREATE ROLE cheesetrap_worker LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'worker_password';
REVOKE ALL ON DATABASE cheesetrap_test FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_proof_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_proof_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_proof_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_proof_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_memory_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_memory_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_memory_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_memory_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

ALTER ROLE cheesetrap_migration SET search_path = pg_catalog, cheesetrap;
ALTER ROLE cheesetrap_api SET search_path = pg_catalog, cheesetrap;
ALTER ROLE cheesetrap_collector SET search_path = pg_catalog, cheesetrap;
ALTER ROLE cheesetrap_worker SET search_path = pg_catalog, cheesetrap;

-- The normal test database is migrated by the runner before requested tests.
-- This second empty database is exclusively for migration/role acceptance tests.
CREATE DATABASE cheesetrap_migration_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_migration_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_migration_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_migration_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

-- Install acceptance owns its singleton admin and collector lease even when
-- go test runs the API, ingestion and acceptance packages concurrently.
CREATE DATABASE cheesetrap_install_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_install_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_install_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_install_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

-- Detection cursor tests own ingestion order independently of other packages.
CREATE DATABASE cheesetrap_detection_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_detection_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_detection_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_detection_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

-- Enrichment tests own expiring contact claims independently of other packages.
CREATE DATABASE cheesetrap_enrichment_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_enrichment_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_enrichment_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_enrichment_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_reporting_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_reporting_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_reporting_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_reporting_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_jobs_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_jobs_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_jobs_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_jobs_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_revision_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_revision_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_revision_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_revision_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_draft_runtime_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_draft_runtime_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_draft_runtime_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_draft_runtime_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_review_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_review_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_review_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_review_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_ruleconfig_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_ruleconfig_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_ruleconfig_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_ruleconfig_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_review_upgrade_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_review_upgrade_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_review_upgrade_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_review_upgrade_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_review_flow_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_review_flow_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_review_flow_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_review_flow_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_approval_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_approval_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_approval_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_approval_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_delivery_upgrade_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_delivery_upgrade_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_delivery_upgrade_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_delivery_upgrade_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;


CREATE DATABASE cheesetrap_automatic_api_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_automatic_api_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_automatic_api_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_automatic_api_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;


CREATE DATABASE cheesetrap_smtp_upgrade_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_smtp_upgrade_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_smtp_upgrade_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_smtp_upgrade_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;





CREATE DATABASE cheesetrap_retry_upgrade_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_retry_upgrade_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_retry_upgrade_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_retry_upgrade_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;



CREATE DATABASE cheesetrap_retention_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_retention_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_retention_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_retention_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_capacity_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_capacity_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_capacity_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_capacity_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_restore_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_restore_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_restore_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_restore_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;

CREATE DATABASE cheesetrap_chunks_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_chunks_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_chunks_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_chunks_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;


-- Isolated mutable policy/result fixtures.
CREATE DATABASE cheesetrap_policy_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_policy_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_policy_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_policy_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;


-- Isolated mutable policy/result fixtures.
CREATE DATABASE cheesetrap_policy_api_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_policy_api_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_policy_api_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_policy_api_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;


-- Isolated mutable policy/result fixtures.
CREATE DATABASE cheesetrap_eventresult_test OWNER postgres;
REVOKE ALL ON DATABASE cheesetrap_eventresult_test FROM PUBLIC;
GRANT CONNECT ON DATABASE cheesetrap_eventresult_test TO cheesetrap_migration, cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
\connect cheesetrap_eventresult_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;
CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;
REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;
REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;
GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api, cheesetrap_collector, cheesetrap_worker;
