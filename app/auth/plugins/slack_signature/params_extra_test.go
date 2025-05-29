package slacksignature

import (
	"math"
	"testing"
)

func TestSlackSignatureParamsFuncs(t *testing.T) {
	s := &SlackSignatureAuth{}
	if s.Name() != "slack_signature" {
		t.Fatalf("name unexpected: %s", s.Name())
	}
	req := s.RequiredParams()
	if len(req) != 1 || req[0] != "secrets" {
		t.Fatalf("required params unexpected: %v", req)
	}
}

func TestAbs(t *testing.T) {
	if abs(-5) != 5 {
		t.Fatalf("abs failed")
	}
	if abs(math.MinInt64) != math.MaxInt64 {
		t.Fatalf("abs minint")
	}
}

func TestSlackSignatureParseParamsError(t *testing.T) {
	s := &SlackSignatureAuth{}
	if _, err := s.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error")
	}
}
