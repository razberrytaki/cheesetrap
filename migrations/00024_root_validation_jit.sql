-- +goose Up
-- Root proofs use bounded indexed reads. Unanalyzed cardinality estimates can
-- otherwise pay JIT compilation cost again for every deferred root validation.
-- Scope this setting to the validator; caller and server JIT settings are unchanged.
ALTER FUNCTION cheesetrap.validate_evidence_root() SET jit=off;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'root_validation_jit_downgrade_requires_review'; END $$;
-- +goose StatementEnd
