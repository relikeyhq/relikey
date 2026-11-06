// SPDX-License-Identifier: EUPL-1.2

package clock

import (
	"encoding/json/v2"
	"os"
	"testing"
	"time"
)

// KeyClerk's conformance vectors for the edge's time (edge protocol 1.5, section 1), in the kcedge testdata.
type timeVectors struct {
	TrustedTime struct {
		Cases []struct {
			Name         string   `json:"name"`
			Wall         string   `json:"wall"`
			WallAtVerify *string  `json:"wall_at_verify"`
			Boot         float64  `json:"boot"`
			BootAtVerify *float64 `json:"boot_at_verify"`
			SameBoot     bool     `json:"same_boot"`
			Expected     struct {
				Live    bool   `json:"live"`
				Skewed  bool   `json:"skewed"`
				Trusted string `json:"trusted"`
			} `json:"expected"`
		} `json:"cases"`
	} `json:"trusted_time"`
	Ratchet struct {
		Cases []struct {
			Name         string  `json:"name"`
			Anchor       string  `json:"anchor"`
			BootAtAnchor float64 `json:"boot_at_anchor"`
			Wakes        []struct {
				Boot float64 `json:"boot"`
				Wall string  `json:"wall"`
			} `json:"wakes"`
			Now struct {
				Boot float64 `json:"boot"`
				Wall string  `json:"wall"`
			} `json:"now"`
			Expected struct {
				Anchor  string `json:"anchor"`
				Trusted string `json:"trusted"`
			} `json:"expected"`
		} `json:"cases"`
	} `json:"ratchet"`
}

const vectorSkew = 300 * time.Second

func loadTimeVectors(t *testing.T) timeVectors {
	t.Helper()
	b, err := os.ReadFile("../kcedge/testdata/edge.json")
	if err != nil {
		t.Fatal(err)
	}
	var v timeVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func at(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func secs(f float64) time.Duration { return time.Duration(f * float64(time.Second)) }

func TestTrustedTimeVectors(t *testing.T) {
	v := loadTimeVectors(t)
	if len(v.TrustedTime.Cases) == 0 {
		t.Fatal("no trusted_time cases")
	}
	for _, c := range v.TrustedTime.Cases {
		t.Run(c.Name, func(t *testing.T) {
			f := &Fake{Wall: at(t, c.Wall), Up: secs(c.Boot)}
			var wallAt time.Time
			bootAt := time.Duration(-1) // no verify point in this boot
			if c.WallAtVerify != nil {
				wallAt = at(t, *c.WallAtVerify)
			}
			if c.BootAtVerify != nil && c.SameBoot {
				bootAt = secs(*c.BootAtVerify)
			}
			got, skewed := Trusted(f, wallAt, bootAt, vectorSkew)
			live := bootAt >= 0 && !wallAt.IsZero()
			if !got.Equal(at(t, c.Expected.Trusted)) || skewed != c.Expected.Skewed || live != c.Expected.Live {
				t.Fatalf("trusted %s skewed %v live %v; want %s %v %v", got.Format(time.RFC3339), skewed, live,
					c.Expected.Trusted, c.Expected.Skewed, c.Expected.Live)
			}
		})
	}
}

func TestRatchetVectors(t *testing.T) {
	v := loadTimeVectors(t)
	if len(v.Ratchet.Cases) == 0 {
		t.Fatal("no ratchet cases")
	}
	for _, c := range v.Ratchet.Cases {
		t.Run(c.Name, func(t *testing.T) {
			anchor, bootAt := at(t, c.Anchor), secs(c.BootAtAnchor)
			for _, w := range c.Wakes {
				anchor, bootAt = Ratchet(anchor, bootAt, secs(w.Boot), at(t, w.Wall))
			}
			if !anchor.Equal(at(t, c.Expected.Anchor)) {
				t.Fatalf("anchor %s, want %s", anchor.Format(time.RFC3339), c.Expected.Anchor)
			}
			got, _ := Trusted(&Fake{Wall: at(t, c.Now.Wall), Up: secs(c.Now.Boot)}, anchor, bootAt, vectorSkew)
			if !got.Equal(at(t, c.Expected.Trusted)) {
				t.Fatalf("trusted %s, want %s", got.Format(time.RFC3339), c.Expected.Trusted)
			}
		})
	}
}

func TestStartTimeVectors(t *testing.T) {
	var v struct {
		StartTime struct {
			Cases []struct {
				Name         string  `json:"name"`
				Wall         string  `json:"wall"`
				SignedAt     string  `json:"signed_at"`
				BootAtSigned float64 `json:"boot_at_signed"`
				Boot         float64 `json:"boot"`
				SameBoot     bool    `json:"same_boot"`
				Expected     struct {
					StartNow *string `json:"start_now"`
				} `json:"expected"`
			} `json:"cases"`
		} `json:"start_time"`
	}
	b, err := os.ReadFile("../kcedge/testdata/edge.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.StartTime.Cases) == 0 {
		t.Fatal("no start_time cases")
	}
	for _, c := range v.StartTime.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, ok := StartTime(at(t, c.Wall), at(t, c.SignedAt), secs(c.BootAtSigned), secs(c.Boot), c.SameBoot)
			switch {
			case c.Expected.StartNow == nil && ok:
				t.Fatalf("start %s, want none", got.Format(time.RFC3339))
			case c.Expected.StartNow != nil && (!ok || !got.Equal(at(t, *c.Expected.StartNow))):
				t.Fatalf("start %s (%v), want %s", got.Format(time.RFC3339), ok, *c.Expected.StartNow)
			}
		})
	}
}
