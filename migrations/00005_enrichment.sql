-- +goose Up
-- Exact-IP cache and expiring ownership claims. A claim is a single statement;
-- no transaction/row lock survives external registry I/O. Tokens fence stale owners.
CREATE TABLE cheesetrap.enrichment_cache (
 address inet PRIMARY KEY,
 result jsonb,
 queried_at timestamptz,
 expires_at timestamptz NOT NULL DEFAULT '-infinity',
 lease_token uuid,
 lease_expires_at timestamptz,
 CHECK(masklen(address)=CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
 CHECK(NOT address <<= '::ffff:0:0/96'::inet),
 CHECK((lease_token IS NULL)=(lease_expires_at IS NULL)),
 CHECK((result IS NULL)=(queried_at IS NULL)),
 CHECK(result IS NULL OR COALESCE(jsonb_typeof(result)='object' AND result->'schema_version'='1'::jsonb,false)),
 CHECK(queried_at IS NULL OR expires_at>queried_at)
);
COMMENT ON COLUMN cheesetrap.enrichment_cache.result IS 'Versioned registry evidence and contact provenance; never permission to send a report.';
GRANT SELECT ON cheesetrap.enrichment_cache TO cheesetrap_api,cheesetrap_worker;
GRANT INSERT,UPDATE ON cheesetrap.enrichment_cache TO cheesetrap_worker;

-- +goose Down
DROP TABLE cheesetrap.enrichment_cache;
