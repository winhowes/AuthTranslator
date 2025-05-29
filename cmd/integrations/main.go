package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/winhowes/AuthTranslator/cmd/integrations/plugins"
)

// exit allows tests to stub os.Exit.
var exit = os.Exit

var server = flag.String("server", "http://localhost:8080/integrations", "integration endpoint")

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `Usage: integrations [options] <list|update|delete|plugin> [plugin options]\n\n`)
	fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintln(flag.CommandLine.Output(), "\nRun \"integrations <plugin> -help\" to see plugin flags.")
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		exit(1)
	}
	cmd := flag.Arg(0)
	args := flag.Args()[1:]

	if cmd == "list" {
		listIntegrations()
		return
	}
	if cmd == "delete" {
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "delete requires integration name")
			exit(1)
		}
		deleteIntegration(args[0])
		return
	}
	if cmd == "update" {
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "update requires plugin name")
			exit(1)
		}
		builder := plugins.Get(args[0])
		if builder == nil {
			fmt.Fprintf(os.Stderr, "unknown plugin %s\n", args[0])
			exit(1)
		}
		integ, err := builder(args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			exit(1)
		}
		sendIntegrationWithMethod(http.MethodPut, integ)
		return
	}

	builder := plugins.Get(cmd)
	if builder == nil {
		fmt.Fprintf(os.Stderr, "unknown plugin %s\n", cmd)
		exit(1)
	}
	integ, err := builder(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
	sendIntegrationWithMethod(http.MethodPost, integ)
}

func sendIntegrationWithMethod(method string, i plugins.Integration) {
	data, err := json.Marshal(i)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
	req, err := http.NewRequest(method, *server, bytes.NewBuffer(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
	defer resp.Body.Close()
	success := http.StatusCreated
	if method == http.MethodPut {
		success = http.StatusOK
	}
	if resp.StatusCode != success {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server error: %s\n%s\n", resp.Status, string(body))
		exit(1)
	}
	if method == http.MethodPost {
		fmt.Println("integration added")
	} else {
		fmt.Println("integration updated")
	}
}

func deleteIntegration(name string) {
	payload := struct {
		Name string `json:"name"`
	}{Name: name}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodDelete, *server, bytes.NewBuffer(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server error: %s\n%s\n", resp.Status, string(body))
		exit(1)
	}
	fmt.Println("integration deleted")
}

func listIntegrations() {
	resp, err := http.Get(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "server error: %s\n%s\n", resp.Status, string(body))
		exit(1)
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(1)
	}
	for _, i := range list {
		fmt.Println(i.Name)
	}
}
