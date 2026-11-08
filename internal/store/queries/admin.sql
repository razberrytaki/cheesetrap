-- API caller owns transactions: lock settings -> change -> append audit ->
-- COMMIT. Hash credentials before BEGIN; no external I/O inside transactions.

-- name: CreateAdmin :one
INSERT INTO cheesetrap.admins(username,password_hash) VALUES($1,$2) RETURNING admin_id,username,created_at;

-- name: GetAdminForLogin :one
SELECT admin_id,username,password_hash FROM cheesetrap.admins WHERE username=$1;

-- name: UpdateAdminPassword :exec
UPDATE cheesetrap.admins SET password_hash=$2,updated_at=clock_timestamp() WHERE admin_id=$1;

-- name: DeleteSession :exec
DELETE FROM cheesetrap.sessions WHERE token_hash=$1;

-- name: DeleteExpiredSessions :execrows
DELETE FROM cheesetrap.sessions WHERE expires_at<=clock_timestamp() OR last_seen_at<=clock_timestamp()-interval '1 hour';

-- name: GetSetting :one
SELECT * FROM cheesetrap.settings WHERE key=$1;

-- name: LockSetting :one
SELECT * FROM cheesetrap.settings WHERE key=$1 FOR UPDATE;

-- name: CreateSetting :one
INSERT INTO cheesetrap.settings(key,version,value) VALUES($1,1,$2) RETURNING *;

-- name: UpdateSetting :one
UPDATE cheesetrap.settings SET value=$2,version=version+1,updated_at=clock_timestamp() WHERE key=$1 AND version=$3 RETURNING *;

-- name: AppendAudit :exec
INSERT INTO cheesetrap.audit(admin_id,action,details) VALUES($1,$2,$3);

-- name: CreateLoginSession :one
WITH moment AS MATERIALIZED (SELECT clock_timestamp() AS at)
INSERT INTO cheesetrap.sessions(token_hash,admin_id,created_at,expires_at,last_seen_at)
SELECT $1,$2,at,at+interval '12 hours',at FROM moment RETURNING expires_at;

-- name: AuthenticateSession :one
-- Lock before sampling the DB clock. Authentication and idle touch are one
-- statement; a concurrent DELETE can never be undone by an UPSERT or retry.
WITH locked AS MATERIALIZED (
 SELECT session_id FROM cheesetrap.sessions WHERE token_hash=$1 FOR UPDATE
), moment AS MATERIALIZED (
 SELECT clock_timestamp() AS at FROM locked
)
UPDATE cheesetrap.sessions s SET last_seen_at=greatest(s.last_seen_at,moment.at)
FROM moment,cheesetrap.admins a
WHERE s.token_hash=$1 AND s.admin_id=a.admin_id
 AND s.expires_at>moment.at AND s.last_seen_at>moment.at-interval '1 hour'
RETURNING s.admin_id,a.username;
