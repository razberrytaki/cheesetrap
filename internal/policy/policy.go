// Package policy shares the validated operational settings used by API and workers.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"strconv"
)

type Retention struct {
	RawDays     int    `json:"raw_days" minimum:"1" maximum:"365"`
	RawBytes    string `json:"raw_bytes" pattern:"^[1-9][0-9]*$" maxLength:"13"`
	EventDays   int    `json:"event_days" minimum:"1" maximum:"3650"`
	HistoryDays int    `json:"history_days" minimum:"1" maximum:"3650"`
	JobDays     int    `json:"job_days" minimum:"1" maximum:"365"`
}
type Values struct {
	Retention Retention `json:"retention"`
}

func Defaults() Values {
	return Values{Retention{7, "1073741824", 30, 180, 7}}
}
func (p Retention) Valid() bool {
	n, e := strconv.ParseInt(p.RawBytes, 10, 64)
	return e == nil && strconv.FormatInt(n, 10) == p.RawBytes && n >= 33554432 && n <= 1099511627776 && p.RawDays >= 1 && p.RawDays <= 365 && p.EventDays >= 1 && p.EventDays <= 3650 && p.HistoryDays >= 1 && p.HistoryDays <= 3650 && p.JobDays >= 1 && p.JobDays <= 365
}

var ErrInvalid = errors.New("invalid_operational_policy")

// Missing legacy fields use the established defaults. Explicit null or invalid
// values fail closed rather than silently selecting a different deletion policy.
func Decode(data []byte) (Values, error) {
	p := Defaults()
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return p, ErrInvalid
	}
	for _, key := range []string{"retention"} {
		if raw, ok := object[key]; ok {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || fields == nil {
				return p, ErrInvalid
			}
			for _, v := range fields {
				if string(v) == "null" {
					return p, ErrInvalid
				}
			}
		}
	}
	if json.Unmarshal(data, &p) != nil || !p.Retention.Valid() {
		return p, ErrInvalid
	}
	return p, nil
}

type Reader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func Read(ctx context.Context, q Reader) (Values, error) {
	var data []byte
	if e := q.QueryRow(ctx, `SELECT value FROM cheesetrap.settings WHERE key='review_policy'`).Scan(&data); e != nil {
		return Values{}, e
	}
	return Decode(data)
}
