package githubsignature

import "testing"

func TestGitHubSignatureParamsFuncs(t *testing.T) {
	g := &GitHubSignatureAuth{}
	if g.Name() != "github_signature" {
		t.Fatalf("name unexpected: %s", g.Name())
	}
	req := g.RequiredParams()
	if len(req) != 1 || req[0] != "secrets" {
		t.Fatalf("required params unexpected: %v", req)
	}
}

func TestGitHubSignatureParseParamsError(t *testing.T) {
	g := &GitHubSignatureAuth{}
	if _, err := g.ParseParams(map[string]interface{}{}); err == nil {
		t.Fatal("expected error")
	}
}
