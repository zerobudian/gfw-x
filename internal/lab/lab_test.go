package lab

import (
	"fmt"
	"os"
	"testing"
)

// TestMain generates the deterministic pcap fixtures before any test runs so
// the repo always has them on disk under testdata/pcaps.
func TestMain(m *testing.M) {
	if err := GenerateFixtures("../../testdata"); err != nil {
		fmt.Fprintf(os.Stderr, "lab: generate fixtures: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestPcapReplayRegression replays each fixture through a real gateway and
// checks the produced event against the expected spec, then prints a summary
// table including precision/recall over the labeled set.
func TestPcapReplayRegression(t *testing.T) {
	cases := []string{"dns_query", "tls_sni"}
	results := make([]caseResult, 0, len(cases))

	for _, name := range cases {
		res := evaluateCase("../../testdata", name)
		results = append(results, res)
		// Keep going through all cases so the summary table is complete; report
		// each failure to the test harness too.
		if !res.Pass {
			t.Errorf("[%s] FAIL: %s", res.CaseName, res.Mismatch)
		}
	}

	printTable(results)
}
