-- name: GetEnrichmentResult :one
SELECT result FROM cheesetrap.enrichment_cache
WHERE address=sqlc.arg(address)::inet AND result IS NOT NULL AND expires_at>clock_timestamp();

-- name: ClaimEnrichment :one
INSERT INTO cheesetrap.enrichment_cache(address,lease_token,lease_expires_at)
VALUES(sqlc.arg(address)::inet,gen_random_uuid(),clock_timestamp()+sqlc.arg(lease_seconds)::integer*interval '1 second')
ON CONFLICT(address) DO UPDATE SET lease_token=EXCLUDED.lease_token,lease_expires_at=EXCLUDED.lease_expires_at
WHERE cheesetrap.enrichment_cache.expires_at<=clock_timestamp()
 AND (cheesetrap.enrichment_cache.lease_token IS NULL OR cheesetrap.enrichment_cache.lease_expires_at<=clock_timestamp())
RETURNING lease_token,clock_timestamp()::timestamptz AS claimed_at;

-- name: CompleteEnrichment :execrows
UPDATE cheesetrap.enrichment_cache
SET result=sqlc.arg(result)::jsonb,queried_at=sqlc.arg(queried_at)::timestamptz,expires_at=sqlc.arg(expires_at)::timestamptz,lease_token=NULL,lease_expires_at=NULL
WHERE address=sqlc.arg(address)::inet AND lease_token=sqlc.arg(lease_token)::uuid AND lease_expires_at>clock_timestamp();

-- name: ReleaseEnrichment :exec
UPDATE cheesetrap.enrichment_cache SET lease_token=NULL,lease_expires_at=NULL
WHERE address=sqlc.arg(address)::inet AND lease_token=sqlc.arg(lease_token)::uuid;

-- A manual request bypasses only an older successful cache entry. Failed/rate
-- limited results keep their retry lifetime; concurrent owners keep the lease.
-- name: ClaimRefreshEnrichment :one
INSERT INTO cheesetrap.enrichment_cache(address,lease_token,lease_expires_at)
VALUES(sqlc.arg(address)::inet,gen_random_uuid(),clock_timestamp()+sqlc.arg(lease_seconds)::integer*interval '1 second')
ON CONFLICT(address) DO UPDATE SET lease_token=EXCLUDED.lease_token,lease_expires_at=EXCLUDED.lease_expires_at
WHERE (cheesetrap.enrichment_cache.expires_at<=clock_timestamp()
 OR (cheesetrap.enrichment_cache.result->>'lookup_succeeded'='true'
  AND cheesetrap.enrichment_cache.queried_at<sqlc.arg(requested_at)::timestamptz
  AND coalesce((cheesetrap.enrichment_cache.result->>'retry_after')::timestamptz,'-infinity')<=clock_timestamp()))
 AND (cheesetrap.enrichment_cache.lease_token IS NULL OR cheesetrap.enrichment_cache.lease_expires_at<=clock_timestamp())
RETURNING lease_token,clock_timestamp()::timestamptz AS claimed_at;
