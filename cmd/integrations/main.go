package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/winhowes/AuthTransformer/cmd/integrations/plugins"
)

var server = flag.String("server", "http://localhost:8080/integrations", "integration endpoint")

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: integrations <list|plugin> [options]")
		os.Exit(1)
	}
	plugin := flag.Arg(0)
	args := flag.Args()[1:]

	switch plugin {
	case "list":
		listIntegrations()
	case "slack":
		fs := flag.NewFlagSet("slack", flag.ExitOnError)
		name := fs.String("name", "slack", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		sign := fs.String("signing-secret", "", "secret reference for signing secret")
		fs.Parse(args)
		if *token == "" || *sign == "" {
			fmt.Fprintln(os.Stderr, "-token and -signing-secret are required")
			os.Exit(1)
		}
		integ := plugins.Slack(*name, *token, *sign)
		sendIntegration(integ)
	case "github":
		fs := flag.NewFlagSet("github", flag.ExitOnError)
		name := fs.String("name", "github", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		secret := fs.String("webhook-secret", "", "secret reference for webhook secret")
		fs.Parse(args)
		if *token == "" || *secret == "" {
			fmt.Fprintln(os.Stderr, "-token and -webhook-secret are required")
			os.Exit(1)
		}
		integ := plugins.GitHub(*name, *token, *secret)
		sendIntegration(integ)
	case "ghe":
		fs := flag.NewFlagSet("ghe", flag.ExitOnError)
		name := fs.String("name", "ghe", "integration name")
		domain := fs.String("domain", "", "GitHub Enterprise domain")
		token := fs.String("token", "", "secret reference for API token")
		secret := fs.String("webhook-secret", "", "secret reference for webhook secret")
		fs.Parse(args)
		if *domain == "" || *token == "" || *secret == "" {
			fmt.Fprintln(os.Stderr, "-domain, -token and -webhook-secret are required")
			os.Exit(1)
		}
		integ := plugins.GitHubEnterprise(*name, *domain, *token, *secret)
		sendIntegration(integ)
	case "jira":
		fs := flag.NewFlagSet("jira", flag.ExitOnError)
		name := fs.String("name", "jira", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.Jira(*name, *token)
		sendIntegration(integ)
	case "linear":
		fs := flag.NewFlagSet("linear", flag.ExitOnError)
		name := fs.String("name", "linear", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.Linear(*name, *token)
		sendIntegration(integ)
	case "gitlab":
		fs := flag.NewFlagSet("gitlab", flag.ExitOnError)
		name := fs.String("name", "gitlab", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.GitLab(*name, *token)
		sendIntegration(integ)
	case "asana":
		fs := flag.NewFlagSet("asana", flag.ExitOnError)
		name := fs.String("name", "asana", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.Asana(*name, *token)
		sendIntegration(integ)
	case "zendesk":
		fs := flag.NewFlagSet("zendesk", flag.ExitOnError)
		name := fs.String("name", "zendesk", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.Zendesk(*name, *token)
		sendIntegration(integ)
	case "servicenow":
		fs := flag.NewFlagSet("servicenow", flag.ExitOnError)
		name := fs.String("name", "servicenow", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.ServiceNow(*name, *token)
		sendIntegration(integ)
	case "sendgrid":
		fs := flag.NewFlagSet("sendgrid", flag.ExitOnError)
		name := fs.String("name", "sendgrid", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.SendGrid(*name, *token)
		sendIntegration(integ)
	case "twilio":
		fs := flag.NewFlagSet("twilio", flag.ExitOnError)
		name := fs.String("name", "twilio", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.Twilio(*name, *token)
		sendIntegration(integ)
	case "stripe":
		fs := flag.NewFlagSet("stripe", flag.ExitOnError)
		name := fs.String("name", "stripe", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.Stripe(*name, *token)
		sendIntegration(integ)
	case "monday":
		fs := flag.NewFlagSet("monday", flag.ExitOnError)
		name := fs.String("name", "monday", "integration name")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" {
			fmt.Fprintln(os.Stderr, "-token is required")
			os.Exit(1)
		}
		integ := plugins.Monday(*name, *token)
		sendIntegration(integ)
	case "okta":
		fs := flag.NewFlagSet("okta", flag.ExitOnError)
		name := fs.String("name", "okta", "integration name")
		domain := fs.String("domain", "", "okta domain, e.g. myorg.okta.com")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" || *domain == "" {
			fmt.Fprintln(os.Stderr, "-token and -domain are required")
			os.Exit(1)
		}
		integ := plugins.Okta(*name, *domain, *token)
		sendIntegration(integ)
	case "workday":
		fs := flag.NewFlagSet("workday", flag.ExitOnError)
		name := fs.String("name", "workday", "integration name")
		domain := fs.String("domain", "", "workday domain, e.g. myorg.workday.com")
		token := fs.String("token", "", "secret reference for API token")
		fs.Parse(args)
		if *token == "" || *domain == "" {
			fmt.Fprintln(os.Stderr, "-token and -domain are required")
			os.Exit(1)
		}
		integ := plugins.Workday(*name, *domain, *token)
		sendIntegration(integ)
	default:
		fmt.Fprintf(os.Stderr, "unknown plugin %s\n", plugin)
		os.Exit(1)
	}
}

func sendIntegration(i plugins.Integration) {
	data, err := json.Marshal(i)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	resp, err := http.Post(*server, "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server error: %s\n%s\n", resp.Status, string(body))
		os.Exit(1)
	}
	fmt.Println("integration added")
}

func listIntegrations() {
	resp, err := http.Get(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server error: %s\n%s\n", resp.Status, string(body))
		os.Exit(1)
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, i := range list {
		fmt.Println(i.Name)
	}
}
