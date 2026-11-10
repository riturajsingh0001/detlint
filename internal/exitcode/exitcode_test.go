package exitcode

import (
	"testing"

	"github.com/riturajsingh0001/detlint/internal/analysis"
)

func TestFromFindings(t *testing.T) {
	findings := []analysis.Finding{
		{Severity: analysis.Info},
		{Severity: analysis.Warning},
	}
	cases := []struct {
		failOn analysis.Severity
		want   int
	}{
		{analysis.Info, Findings},
		{analysis.Warning, Findings},
		{analysis.Error, Clean},
		{analysis.Severity(99), Clean},
	}
	for _, tc := range cases {
		if got := FromFindings(findings, tc.failOn); got != tc.want {
			t.Errorf("FromFindings(failOn=%v) = %d, want %d", tc.failOn, got, tc.want)
		}
	}
}

func TestFromFindingsEmpty(t *testing.T) {
	if got := FromFindings(nil, analysis.Info); got != Clean {
		t.Fatalf("empty findings = %d", got)
	}
}

func TestFromSeverity(t *testing.T) {
	if got := FromSeverity(analysis.Error, analysis.Warning); got != Findings {
		t.Fatalf("error >= warning = %d", got)
	}
	if got := FromSeverity(analysis.Info, analysis.Warning); got != Clean {
		t.Fatalf("info < warning = %d", got)
	}
	if got := FromSeverity(analysis.Error, analysis.Severity(99)); got != Clean {
		t.Fatalf("never = %d", got)
	}
}
