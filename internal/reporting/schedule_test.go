package reporting

import (
	"testing"
	"time"

	"cheesetrap/internal/store/db"
)

func TestCalendarBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, zone, start, want string
		days                    int
	}{
		{"leap", "UTC", "2024-02-28T00:00:00Z", "2024-02-29T00:00:00Z", 1},
		{"year", "UTC", "2026-12-31T00:00:00Z", "2027-01-01T00:00:00Z", 1},
		{"spring_dst", "America/New_York", "2026-03-08T05:00:00Z", "2026-03-09T04:00:00Z", 1},
		{"autumn_dst", "America/New_York", "2026-11-01T04:00:00Z", "2026-11-02T05:00:00Z", 1},
		{"transition", "Asia/Tokyo", "2026-01-01T00:00:00Z", "2026-01-01T15:00:00Z", 1},
		{"period", "UTC", "2026-12-31T00:00:00Z", "2027-01-07T00:00:00Z", 7},
		{"missing_midnight", "America/Santiago", "2026-09-05T04:00:00Z", "2026-09-06T04:00:00Z", 1},
		{"repeated_midnight_chooses_first", "America/Havana", "2026-10-31T04:00:00Z", "2026-11-01T04:00:00Z", 1},
		{"skipped_civil_date", "Pacific/Apia", "2011-12-29T10:00:00Z", "2011-12-30T10:00:00Z", 1},
		{"cadence_after_skipped_date", "Pacific/Apia", "2011-12-30T10:00:00Z", "2012-01-01T10:00:00Z", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, _ := time.Parse(time.RFC3339, tc.start)
			want, _ := time.Parse(time.RFC3339, tc.want)
			got, err := nextBoundary(start, tc.zone, tc.days)
			if err != nil || !got.Equal(want) || !got.After(start) {
				t.Fatalf("boundary=%s err=%v want=%s", got, err, want)
			}
		})
	}
	for _, zone := range []string{"", "Local", "../UTC", "invalid"} {
		if _, err := nextBoundary(time.Now(), zone, 1); err == nil {
			t.Fatal("invalid timezone accepted", zone)
		}
	}
	for _, days := range []int{0, 32} {
		if _, err := nextBoundary(time.Now(), "UTC", days); err == nil {
			t.Fatal("invalid period accepted")
		}
	}
}

func TestCurrentEndMatchesCalendarSequence(t *testing.T) {
	for _, tc := range []struct {
		zone, start, now string
		days             int
	}{
		{"America/Santiago", "2026-09-02T04:00:00Z", "2026-09-07T15:00:00Z", 2},
		{"America/Santiago", "2026-09-01T00:00:00Z", "2026-09-07T15:00:00Z", 2},
		{"America/Havana", "2026-10-29T04:00:00Z", "2026-11-01T04:30:00Z", 2},
		{"America/Havana", "2026-10-29T04:00:00Z", "2026-11-01T05:30:00Z", 2},
		{"Pacific/Apia", "2011-12-25T00:00:00Z", "2012-01-02T00:00:00Z", 2},
		{"Pacific/Kwajalein", "1993-08-15T00:00:00Z", "1993-08-23T00:00:00Z", 3},
	} {
		t.Run(tc.zone+"/"+tc.start+"/"+tc.now, func(t *testing.T) {
			start, _ := time.Parse(time.RFC3339, tc.start)
			now, _ := time.Parse(time.RFC3339, tc.now)
			schedule := db.CheesetrapReportingScheduleVersion{Timezone: tc.zone, PeriodDays: int32(tc.days), EffectiveFrom: stamp(start)}
			want := start
			for !want.After(now) {
				next, err := nextBoundary(want, tc.zone, tc.days)
				if err != nil || !next.After(want) {
					t.Fatal("calendar stopped advancing", err)
				}
				want = next
			}
			got, err := currentEnd(now, schedule)
			if err != nil || !got.After(now) || !got.Equal(want) {
				t.Fatalf("currentEnd=%s sequential=%s now=%s err=%v", got, want, now, err)
			}
		})
	}
}

func TestCurrentEndCalculationBound(t *testing.T) {
	schedule := db.CheesetrapReportingScheduleVersion{Timezone: "UTC", PeriodDays: 1, EffectiveFrom: stamp(time.Date(1700, 1, 1, 0, 0, 0, 0, time.UTC))}
	if _, err := currentEnd(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), schedule); err != ErrSchedule {
		t.Fatal("excessive calendar computation did not fail closed", err)
	}
}
