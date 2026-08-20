package agent

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestLiveNVDParse(t *testing.T) {
	resp, err := http.Get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-24813")
	if err != nil {
		t.Skip("network unavailable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 300000))
	out := parseCVEJSON(body)
	t.Logf("OUTPUT:\n%s", out)
	if !strings.Contains(out, "CVE-2025-24813") || !strings.Contains(out, "CRITICAL") || !strings.Contains(out, "9.8") {
		t.Fatalf("parse failed, output:\n%s", out)
	}
}