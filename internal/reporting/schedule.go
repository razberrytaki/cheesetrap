package reporting

import (
	"context"
	"errors"
	"strings"
	"time"
	_ "time/tzdata" // release images need no host timezone database

	"cheesetrap/internal/store/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSchedule = errors.New("report_schedule_invalid")

func location(zone string, days int) (*time.Location, error) {
	if days < 1 || days > 31 || zone == "" || zone == "Local" || strings.HasPrefix(zone, "/") || strings.Contains(zone, "..") {
		return nil, ErrSchedule
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return nil, ErrSchedule
	}
	return loc, nil
}

// A changed timezone has one transition interval starting at the old end.
// Each next boundary advances period_days from the start's actual local date.
// Missing midnight uses the date's first actual instant; a wholly skipped date
// uses the next existing date. Repeated midnight uses its first occurrence.
func nextBoundary(start time.Time, zone string, days int) (time.Time, error) {
	loc, err := location(zone, days)
	if err != nil {
		return time.Time{}, err
	}
	return nextBoundaryIn(start, loc, days)
}
func nextBoundaryIn(start time.Time, loc *time.Location, days int) (time.Time, error) {
	y, m, d := start.In(loc).Date()
	date := time.Date(y, m, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days)
	end, err := firstInstantOfDate(date, loc)
	if err != nil || !end.After(start) {
		return time.Time{}, ErrSchedule
	}
	return end, nil
}

// Resolve a civil midnight against chronological constant-offset intervals,
// avoiding time.Date's unspecified choice during a timezone gap or fold. IANA
// offsets and date-line changes fit within this 96-hour search neighborhood.
// An interval beginning after the requested midnight supplies the first actual
// instant after a gap; visiting intervals in time order selects the first fold.
func firstInstantOfDate(date time.Time, loc *time.Location) (time.Time, error) {
	cursor, limit := date.Add(-48*time.Hour), date.Add(48*time.Hour)
	for cursor.Before(limit) {
		local := cursor.In(loc)
		_, offset := local.Zone()
		_, zoneEnd := local.ZoneBounds()
		candidate := date.Add(-time.Duration(offset) * time.Second)
		if candidate.Before(cursor) {
			candidate = cursor
		}
		if candidate.Before(limit) && (zoneEnd.IsZero() || candidate.Before(zoneEnd)) {
			return candidate.UTC(), nil
		}
		if zoneEnd.IsZero() || !zoneEnd.After(cursor) {
			break
		}
		cursor = zoneEnd
	}
	return time.Time{}, ErrSchedule
}

const maxScheduleBoundaries = 100_000

// Use exactly the same calendar sequence as reconciliation. Calendar arithmetic
// from a separate anchor can change phase after a skipped date. The finite cap
// bounds work under the cursor lock (over 273 years even for daily intervals);
// exceeding it fails the whole settings transaction instead of backdating it.
func currentEnd(now time.Time, s db.CheesetrapReportingScheduleVersion) (time.Time, error) {
	loc, err := location(s.Timezone, int(s.PeriodDays))
	if err != nil {
		return time.Time{}, err
	}
	if s.EffectiveFrom.InfinityModifier == pgtype.NegativeInfinity {
		return nextBoundaryIn(now, loc, int(s.PeriodDays))
	}
	if !s.EffectiveFrom.Valid || s.EffectiveFrom.InfinityModifier != pgtype.Finite || now.Before(s.EffectiveFrom.Time) {
		return time.Time{}, ErrSchedule
	}
	end := s.EffectiveFrom.Time
	for range maxScheduleBoundaries {
		end, err = nextBoundaryIn(end, loc, int(s.PeriodDays))
		if err != nil {
			return time.Time{}, err
		}
		if end.After(now) {
			return end, nil
		}
	}
	return time.Time{}, ErrSchedule
}

// ChangeSchedule is an internal domain operation; the settings API is a later
// milestone. It samples the DB clock only after acquiring the shared lock. A
// change affects the next unopened interval at the change time, even if the
// durable catch-up cursor is months behind. Versions are append-only; a newer
// version wins when multiple changes share the same effective boundary.
func ChangeSchedule(ctx context.Context, pool *pgxpool.Pool, zone string, days int) (db.CheesetrapReportingScheduleVersion, error) {
	if _, err := location(zone, days); err != nil {
		return db.CheesetrapReportingScheduleVersion{}, err
	}
	if pool == nil {
		return db.CheesetrapReportingScheduleVersion{}, ErrWindow
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return db.CheesetrapReportingScheduleVersion{}, windowError(ctx)
	}
	defer tx.Rollback(context.Background())
	result, err := ChangeScheduleTx(ctx, tx, zone, days)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, windowError(ctx)
	}
	return result, nil
}

// ChangeScheduleTx preserves processing -> schedule cursor -> window lock order.
func ChangeScheduleTx(ctx context.Context, tx pgx.Tx, zone string, days int) (db.CheesetrapReportingScheduleVersion, error) {
	if _, err := location(zone, days); err != nil {
		return db.CheesetrapReportingScheduleVersion{}, err
	}
	var err error
	q := db.New(tx)
	if _, err = q.LockProcessingCursors(ctx); err != nil {
		return db.CheesetrapReportingScheduleVersion{}, windowError(ctx)
	}
	_, now, err := initializeSchedule(ctx, q)
	if err != nil {
		return db.CheesetrapReportingScheduleVersion{}, windowError(ctx)
	}
	active, err := q.ReportScheduleAt(ctx, now)
	if err != nil {
		return active, windowError(ctx)
	}
	end, err := currentEnd(now.Time, active)
	if err != nil {
		return active, err
	}
	w, err := q.GetReportWindowContaining(ctx, now)
	if err == nil {
		end = w.EndAt.Time
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return active, windowError(ctx)
	}
	result, err := q.InsertReportSchedule(ctx, db.InsertReportScheduleParams{Timezone: zone, PeriodDays: int32(days), EffectiveFrom: stamp(end)})
	if err != nil {
		return result, windowError(ctx)
	}
	return result, nil
}

// The caller holds the processing cursor lock. Anchor coverage before allowing
// any later collector to sample its clock: even the first open interval needs
// a floor against clock rollback. Updating the cursor and floor in this same
// transaction also keeps failed River registration or settings changes atomic.
func initializeSchedule(ctx context.Context, q *db.Queries) (start, now pgtype.Timestamptz, err error) {
	start, err = q.LockReportScheduleCursor(ctx)
	if err != nil {
		return start, now, err
	}
	now, err = q.ReportingClock(ctx)
	if err != nil {
		return start, now, err
	}
	if !start.Valid {
		start, err = q.FirstReportDay(ctx, now)
		if err != nil {
			return start, now, err
		}
		if err = q.SetReportScheduleCursor(ctx, start); err != nil {
			return start, now, err
		}
	}
	if err = q.AdvanceSealedBefore(ctx, start); err != nil {
		return start, now, err
	}
	// Existing events may anchor the first interval after the current wall clock.
	// Use the newly persisted anchor for both reconciliation and settings timing.
	now, err = q.ReportingClock(ctx)
	return start, now, err
}
