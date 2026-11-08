package api

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/enrichment"
	"cheesetrap/internal/policy"
	"cheesetrap/internal/reporting"
	"cheesetrap/internal/store/db"
	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
)

type Settings struct {
	Retention            policy.Retention `json:"retention"`
	Version              string           `json:"version"`
	ReplyTo              string           `json:"reply_to"`
	Timezone             string           `json:"timezone"`
	PeriodDays           int              `json:"period_days"`
	ScheduleVersion      string           `json:"schedule_version"`
	RuleEffectiveFromSeq string           `json:"rule_effective_from_seq"`
	Rules                detection.Config `json:"rules"`
}

// UnmarshalJSON also normalizes responses persisted by the pre-policy
// idempotency implementation, not only the current settings document.
func (s *Settings) UnmarshalJSON(data []byte) error {
	type plain Settings
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	operational, err := policy.Decode(data)
	if err != nil {
		return err
	}
	value.Retention = operational.Retention
	*s = Settings(value)
	return nil
}

// ScheduleStatus describes draft evidence aggregation, never mail delivery.
type ScheduleStatus struct {
	Version       string `json:"version"`
	Timezone      string `json:"timezone"`
	PeriodDays    int    `json:"period_days"`
	EffectiveFrom string `json:"effective_from"`
}
type settingsOutput struct {
	Body struct {
		Settings
		ActiveSchedule  ScheduleStatus  `json:"active_schedule"`
		PendingSchedule *ScheduleStatus `json:"pending_schedule"`
	}
}
type settingsPatchInput struct {
	Key  string `header:"Idempotency-Key" required:"true" minLength:"1" maxLength:"128"`
	Body struct {
		Retention       *policy.Retention `json:"retention,omitempty"`
		ExpectedVersion string            `json:"expected_version" pattern:"^[1-9][0-9]*$" maxLength:"19"`
		ReplyTo         *string           `json:"reply_to,omitempty" maxLength:"254"`
		Timezone        *string           `json:"timezone,omitempty" minLength:"1" maxLength:"100"`
		PeriodDays      *int              `json:"period_days,omitempty" minimum:"1" maximum:"31"`
		Rules           *detection.Config `json:"rules,omitempty"`
	}
}
type settingsMutationOutput struct{ Body Settings }

func (s *server) registerSettings(a huma.API) {
	huma.Register(a, s.reviewOperation("settings-get", "GET", "/api/v1/settings"), func(ctx context.Context, _ *struct{}) (*settingsOutput, error) {
		// One statement provides one MVCC snapshot and one reference time for
		// settings and both schedule views, even if a PATCH commits or an
		// effective boundary passes while the response is being assembled.
		var version int64
		var settingsData, activeData, pendingData []byte
		err := s.pool.QueryRow(ctx, `WITH moment AS MATERIALIZED (SELECT statement_timestamp() AS at)
 SELECT s.version,s.value,
  jsonb_build_object('version',active.version::text,'timezone',active.timezone,'period_days',active.period_days,'effective_from',active.effective_from::text),
  (SELECT jsonb_build_object('version',p.version::text,'timezone',p.timezone,'period_days',p.period_days,'effective_from',p.effective_from::text)
   FROM cheesetrap.reporting_schedule_versions p WHERE p.effective_from>moment.at ORDER BY p.effective_from,p.version DESC LIMIT 1)
 FROM cheesetrap.settings s CROSS JOIN moment
 CROSS JOIN LATERAL (SELECT version,timezone,period_days,effective_from FROM cheesetrap.reporting_schedule_versions
  WHERE effective_from<=moment.at ORDER BY effective_from DESC,version DESC LIMIT 1) active
 WHERE s.key='review_policy'`).Scan(&version, &settingsData, &activeData, &pendingData)
		if err != nil {
			return nil, apiError(503)
		}
		out := &settingsOutput{}
		if json.Unmarshal(settingsData, &out.Body.Settings) != nil || json.Unmarshal(activeData, &out.Body.ActiveSchedule) != nil {
			return nil, apiError(503)
		}
		operational, e := policy.Decode(settingsData)
		if e != nil {
			return nil, apiError(503)
		}
		out.Body.Retention = operational.Retention
		out.Body.Version = strconv.FormatInt(version, 10)
		if len(pendingData) > 0 {
			out.Body.PendingSchedule = &ScheduleStatus{}
			if json.Unmarshal(pendingData, out.Body.PendingSchedule) != nil {
				return nil, apiError(503)
			}
		}
		return out, nil
	})
	huma.Register(a, s.reviewOperation("settings-patch", "PATCH", "/api/v1/settings"), func(ctx context.Context, in *settingsPatchInput) (*settingsMutationOutput, error) {
		expected, err := parseVersion(in.Body.ExpectedVersion)
		if err != nil {
			return nil, err
		}
		if in.Body.ReplyTo == nil && in.Body.Timezone == nil && in.Body.PeriodDays == nil && in.Body.Rules == nil && in.Body.Retention == nil {
			return nil, apiError(400)
		}
		if in.Body.Retention != nil && !in.Body.Retention.Valid() {
			return nil, apiError(400)
		}
		if in.Body.ReplyTo != nil && *in.Body.ReplyTo != "" {
			address, ok := enrichment.Mailbox(*in.Body.ReplyTo)
			if !ok {
				return nil, apiError(400)
			}
			in.Body.ReplyTo = &address
		}
		if in.Body.Rules != nil && !in.Body.Rules.Valid() {
			return nil, apiError(400)
		}
		if in.Body.Timezone != nil {
			zone := *in.Body.Timezone
			if zone == "Local" || zone == "" {
				return nil, apiError(400)
			}
			if _, err = time.LoadLocation(zone); err != nil {
				return nil, apiError(400)
			}
		}
		result, err := idempotent(ctx, s, in.Key, "PATCH", "/api/v1/settings", in.Body, 200, func(tx pgx.Tx) (Settings, error) {
			var result Settings
			q := db.New(tx)
			cursors, err := q.LockProcessingCursors(ctx)
			if err != nil {
				return result, err
			}
			var version int64
			var data []byte
			if err = tx.QueryRow(ctx, `SELECT version,value FROM cheesetrap.settings WHERE key='review_policy' FOR UPDATE`).Scan(&version, &data); err != nil {
				return result, err
			}
			if version != expected {
				return result, apiError(409)
			}
			if json.Unmarshal(data, &result) != nil {
				return result, apiError(503)
			}
			operational, err := policy.Decode(data)
			if err != nil {
				return result, apiError(503)
			}
			result.Retention = operational.Retention
			if in.Body.Retention != nil {
				result.Retention = *in.Body.Retention
			}
			if in.Body.ReplyTo != nil {
				result.ReplyTo = *in.Body.ReplyTo
				if err = q.SetReportReplyTo(ctx, result.ReplyTo); err != nil {
					return result, err
				}
			}
			if in.Body.Timezone != nil {
				result.Timezone = *in.Body.Timezone
			}
			if in.Body.PeriodDays != nil {
				result.PeriodDays = *in.Body.PeriodDays
			}
			if in.Body.Timezone != nil || in.Body.PeriodDays != nil {
				schedule, err := reporting.ChangeScheduleTx(ctx, tx, result.Timezone, result.PeriodDays)
				if err != nil {
					return result, err
				}
				result.ScheduleVersion = strconv.FormatInt(schedule.Version, 10)
			}
			if in.Body.Rules != nil {
				result.Rules = *in.Body.Rules
			}
			if !result.Rules.Valid() || cursors.IngestedSeq == 9223372036854775807 {
				return result, apiError(400)
			}
			result.Version = strconv.FormatInt(version+1, 10)
			result.RuleEffectiveFromSeq = strconv.FormatInt(cursors.IngestedSeq+1, 10)
			config, _ := json.Marshal(result.Rules)
			if _, err = tx.Exec(ctx, `INSERT INTO cheesetrap.rule_config_versions(settings_version,effective_from_seq,config) VALUES($1,$2,$3)`, version+1, cursors.IngestedSeq+1, config); err != nil {
				return result, err
			}
			data, _ = json.Marshal(result)
			if _, err = tx.Exec(ctx, `UPDATE cheesetrap.settings SET version=version+1,value=$1,updated_at=clock_timestamp() WHERE key='review_policy'`, data); err != nil {
				return result, err
			}
			// Version-bound refresh requests are fenced even when a worker is already
			// outside the transaction. Their terminal status prevents repair loops.
			if _, err = tx.Exec(ctx, `UPDATE cheesetrap.contact_refresh_requests SET status='superseded',completed_at=clock_timestamp() WHERE status='queued'`); err != nil {
				return result, err
			}
			return result, reviewAudit(ctx, tx, "settings_changed", map[string]any{"version": result.Version, "rule_effective_from_seq": result.RuleEffectiveFromSeq, "schedule_version": result.ScheduleVersion, "retention": result.Retention})
		})
		if err != nil {
			return nil, err
		}
		return &settingsMutationOutput{Body: result}, nil
	})
}
