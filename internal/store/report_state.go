package store

// ReportStateSQL projects stored reports to management states using table alias r.
const ReportStateSQL = `CASE WHEN r.delivery_uncertain OR EXISTS(SELECT 1 FROM cheesetrap.delivery_attempts d WHERE d.report_id=r.report_id) THEN 'archived' WHEN r.state IN ('needs_review','held','rejected') THEN r.state ELSE 'archived' END`
