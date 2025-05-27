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
		fmt.Fprintln(os.Stderr, "usage: integrations <plugin> [options]")
		os.Exit(1)
	}
	plugin := flag.Arg(0)
	args := flag.Args()[1:]

	builder := plugins.Get(plugin)
	if builder == nil {
		fmt.Fprintf(os.Stderr, "unknown plugin %s\n", plugin)
		os.Exit(1)
	}
	integ, err := builder(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sendIntegration(integ)
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
