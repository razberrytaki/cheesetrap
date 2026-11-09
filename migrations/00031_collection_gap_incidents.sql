-- +goose Up
CREATE TABLE cheesetrap.collection_gap_incidents (
 incident_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 sensor_id uuid NOT NULL REFERENCES cheesetrap.sensors,
 started_at timestamptz NOT NULL,
 observed_through timestamptz NOT NULL CHECK(observed_through>=started_at),
 causes text[] NOT NULL CHECK(cardinality(causes)>0 AND array_position(causes,NULL) IS NULL AND causes <@ ARRAY['retention_cleanup','storage_restricted','source_change','legacy']),
 gap_count bigint NOT NULL DEFAULT 0 CHECK(gap_count>=0)
);
CREATE INDEX collection_gap_incidents_latest_idx ON cheesetrap.collection_gap_incidents(sensor_id,observed_through DESC,incident_id DESC);
CREATE INDEX collection_gap_incidents_overlap_idx ON cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through);
INSERT INTO cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through,causes,gap_count)
 SELECT sensor_id,started_at,observed_through,ARRAY['legacy'],gap_count FROM cheesetrap.ingestion_gaps;
GRANT SELECT ON cheesetrap.collection_gap_incidents TO cheesetrap_collector,cheesetrap_api,cheesetrap_worker;
GRANT INSERT,UPDATE ON cheesetrap.collection_gap_incidents TO cheesetrap_collector;
GRANT USAGE ON SEQUENCE cheesetrap.collection_gap_incidents_incident_id_seq TO cheesetrap_collector;

-- +goose StatementBegin
CREATE FUNCTION cheesetrap.note_collection_gap(sensor uuid,since timestamptz,cause text,amount bigint)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,cheesetrap AS $$
DECLARE latest cheesetrap.collection_gap_incidents; at_time timestamptz;
BEGIN
 IF cause IS NULL OR cause NOT IN ('retention_cleanup','storage_restricted','source_change','legacy') OR since IS NULL OR amount IS NULL THEN
  RAISE EXCEPTION 'invalid_collection_gap';
 END IF;
 SELECT * INTO latest FROM cheesetrap.collection_gap_incidents WHERE sensor_id=sensor
 ORDER BY observed_through DESC,incident_id DESC LIMIT 1 FOR UPDATE;
 at_time:=clock_timestamp();
 IF latest.incident_id IS NOT NULL AND latest.observed_through>=at_time-interval '10 minutes' THEN
  UPDATE cheesetrap.collection_gap_incidents SET observed_through=at_time,started_at=least(started_at,since,at_time),
   causes=ARRAY(SELECT DISTINCT c FROM unnest(latest.causes || ARRAY[cause]) c ORDER BY c),
   gap_count=gap_count+greatest(amount,0) WHERE incident_id=latest.incident_id;
 ELSE
  INSERT INTO cheesetrap.collection_gap_incidents(sensor_id,started_at,observed_through,causes,gap_count)
   VALUES(sensor,least(since,at_time),at_time,ARRAY[cause],greatest(amount,0));
 END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cheesetrap.note_collection_gap(uuid,timestamptz,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cheesetrap.note_collection_gap(uuid,timestamptz,text,bigint) TO cheesetrap_collector;

-- +goose Down
DROP FUNCTION cheesetrap.note_collection_gap(uuid,timestamptz,text,bigint);
DROP TABLE cheesetrap.collection_gap_incidents;
