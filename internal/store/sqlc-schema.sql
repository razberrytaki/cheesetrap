-- Static sqlc catalog only. Actual schema ownership is provisioned separately
-- before Goose runs; runtime migrations do not require database CREATE rights.
CREATE SCHEMA cheesetrap;
