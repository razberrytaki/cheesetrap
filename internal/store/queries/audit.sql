-- name: AppendReviewAudit :exec
INSERT INTO cheesetrap.audit(admin_id,action,details) VALUES($1,$2,$3);

-- name: GetReviewIdempotency :one
SELECT request_hash,status,response FROM cheesetrap.review_idempotency WHERE admin_id=$1 AND key=$2;

-- name: SaveReviewIdempotency :exec
INSERT INTO cheesetrap.review_idempotency(admin_id,key,request_hash,status,response) VALUES($1,$2,$3,$4,$5);

-- name: RuleConfigAt :one
SELECT * FROM cheesetrap.rule_config_versions WHERE effective_from_seq<=$1 ORDER BY effective_from_seq DESC,settings_version DESC LIMIT 1;
