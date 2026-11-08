-- +goose Up
-- A revision signs a sealed manifest. Immutable, bounded parts hold the complete
-- evidence/rule copies independently of retained events and detection roots.
CREATE TABLE cheesetrap.report_proofs (
 report_id uuid PRIMARY KEY REFERENCES cheesetrap.reports,
 scheme text NOT NULL DEFAULT 'sha256-parts-v1' CHECK(scheme='sha256-parts-v1'),
 evidence_count bigint NOT NULL DEFAULT 0 CHECK(evidence_count>=0),
 rule_count bigint NOT NULL DEFAULT 0 CHECK(rule_count>=0),
 evidence_hash text NOT NULL DEFAULT '',rules_hash text NOT NULL DEFAULT '',
 sealed boolean NOT NULL DEFAULT false
);
CREATE TABLE cheesetrap.report_proof_parts (
 report_id uuid NOT NULL REFERENCES cheesetrap.report_proofs,
 kind text NOT NULL CHECK(kind IN ('evidence','rules')),
 ordinal bigint NOT NULL CHECK(ordinal>=0),
 first_item bigint NOT NULL CHECK(first_item>=0),
 item_count integer NOT NULL CHECK(item_count BETWEEN 1 AND 32),
 payload bytea NOT NULL CHECK(octet_length(payload)>0),
 PRIMARY KEY(report_id,kind,ordinal),UNIQUE(report_id,kind,first_item)
);
GRANT SELECT,INSERT ON cheesetrap.report_proofs,cheesetrap.report_proof_parts TO cheesetrap_worker,cheesetrap_api;

-- The hash commits to exact stored UTF-8 bytes and part order. Item counts and
-- continuous item offsets are independently checked at seal time.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.report_part_step(s bytea,p bytea) RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT sha256(coalesce(s,sha256(convert_to('cheesetrap:report:sha256-parts-v1','UTF8')))||sha256(p))
$$;
-- +goose StatementEnd
CREATE AGGREGATE cheesetrap.report_part_hash(bytea) (SFUNC=cheesetrap.report_part_step,STYPE=bytea);

-- All writers lock the manifest, including appenders. Once sealed, neither a
-- changed part nor a newly appended part can alter the approved proof.
-- +goose StatementBegin
CREATE FUNCTION cheesetrap.guard_report_proof() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap AS $$
DECLARE s boolean; data jsonb;
BEGIN
 IF TG_OP='DELETE' AND session_user='cheesetrap_worker' AND current_user=pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname='cheesetrap')) THEN RETURN OLD; END IF;
 IF TG_TABLE_NAME='report_proofs' THEN
  IF TG_OP='INSERT' AND NOT NEW.sealed AND NEW.evidence_count=0 AND NEW.rule_count=0 AND NEW.evidence_hash='' AND NEW.rules_hash='' THEN RETURN NEW; END IF;
  IF TG_OP='UPDATE' AND NOT OLD.sealed AND NEW.sealed AND NEW.report_id=OLD.report_id AND NEW.scheme=OLD.scheme AND current_user=pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname='cheesetrap')) THEN RETURN NEW; END IF;
 ELSE
  IF TG_OP='INSERT' THEN
   SELECT sealed INTO s FROM cheesetrap.report_proofs WHERE report_id=NEW.report_id FOR UPDATE;
   IF s=false THEN
    data:=convert_from(NEW.payload,'UTF8')::jsonb;
    IF jsonb_typeof(data)='array' AND jsonb_array_length(data)=NEW.item_count AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(data) e WHERE jsonb_typeof(e)<>'object') THEN RETURN NEW; END IF;
   END IF;
  END IF;
 END IF;
 RAISE EXCEPTION 'report_proof_immutable' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER guard_report_proof BEFORE INSERT OR UPDATE OR DELETE ON cheesetrap.report_proofs FOR EACH ROW EXECUTE FUNCTION cheesetrap.guard_report_proof();
CREATE TRIGGER guard_report_part BEFORE INSERT OR UPDATE OR DELETE ON cheesetrap.report_proof_parts FOR EACH ROW EXECUTE FUNCTION cheesetrap.guard_report_proof();

-- +goose StatementBegin
CREATE FUNCTION cheesetrap.seal_report_proof(id uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,cheesetrap SET work_mem='4MB' SET jit=off AS $$
DECLARE p cheesetrap.report_proofs; e bigint; r bigint; eh text; rh text;
BEGIN
 SELECT * INTO p FROM cheesetrap.report_proofs WHERE report_id=id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'missing_report_proof' USING ERRCODE='23514'; END IF;
 IF NOT p.sealed THEN
  IF EXISTS(SELECT 1 FROM (
   SELECT ordinal,first_item,row_number() OVER(PARTITION BY kind ORDER BY ordinal)-1 AS expected_ordinal,
   coalesce(sum(item_count) OVER(PARTITION BY kind ORDER BY ordinal ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING),0) AS expected_first
   FROM cheesetrap.report_proof_parts WHERE report_id=id) n WHERE ordinal<>expected_ordinal OR first_item<>expected_first) THEN RAISE EXCEPTION 'incomplete_report_proof' USING ERRCODE='23514'; END IF;
  SELECT coalesce(sum(item_count),0),encode(cheesetrap.report_part_hash(payload ORDER BY ordinal),'hex') INTO e,eh FROM cheesetrap.report_proof_parts WHERE report_id=id AND kind='evidence';
  SELECT coalesce(sum(item_count),0),encode(cheesetrap.report_part_hash(payload ORDER BY ordinal),'hex') INTO r,rh FROM cheesetrap.report_proof_parts WHERE report_id=id AND kind='rules';
  IF e=0 OR r=0 THEN RAISE EXCEPTION 'empty_report_proof' USING ERRCODE='23514'; END IF;
  UPDATE cheesetrap.report_proofs SET evidence_count=e,rule_count=r,evidence_hash=eh,rules_hash=rh,sealed=true WHERE report_id=id RETURNING * INTO p;
 END IF;
 RETURN to_jsonb(p)-'report_id'-'sealed';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.seal_report_proof(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cheesetrap.seal_report_proof(uuid) TO cheesetrap_worker,cheesetrap_api;

-- +goose StatementBegin
CREATE FUNCTION cheesetrap.check_revision_proof() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,cheesetrap AS $$
DECLARE manifest jsonb;
BEGIN
 IF NEW.snapshot ? 'proof' THEN
  SELECT to_jsonb(p)-'report_id'-'sealed' INTO manifest FROM cheesetrap.report_proofs p WHERE report_id=NEW.report_id AND sealed;
  IF manifest IS NULL OR manifest IS DISTINCT FROM NEW.snapshot->'proof' OR coalesce(NEW.snapshot->'evidence','null')<>'null'::jsonb OR coalesce(NEW.snapshot->'rules','null')<>'null'::jsonb THEN RAISE EXCEPTION 'invalid_revision_proof' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER check_revision_proof BEFORE INSERT ON cheesetrap.report_revisions FOR EACH ROW EXECUTE FUNCTION cheesetrap.check_revision_proof();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'report_proof_downgrade_requires_data_preservation'; END $$;
-- +goose StatementEnd
