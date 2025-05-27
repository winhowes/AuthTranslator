package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/winhowes/AuthTransformer/cmd/allowlist/plugins"
)

var file = flag.String("file", "allowlist.json", "allowlist file")

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
	}
	switch flag.Arg(0) {
	case "list":
		listCaps()
	case "add":
		addEntry(flag.Args()[1:])
	default:
		usage()
	}
}

func usage() {
	fmt.Println("usage: allowlist <list|add> [options]")
	os.Exit(1)
}

func listCaps() {
	for integ, caps := range plugins.List() {
		fmt.Println(integ + ":")
		for name, spec := range caps {
			fmt.Printf("  %s (params: %s)\n", name, strings.Join(spec.Params, ","))
		}
	}
}

func addEntry(args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	integ := fs.String("integration", "", "integration name")
	caller := fs.String("caller", "", "caller id")
	capName := fs.String("capability", "", "capability name")
	paramList := fs.String("params", "", "comma separated key=value")
	fs.Parse(args)
	if *integ == "" || *caller == "" || *capName == "" {
		fmt.Println("-integration, -caller and -capability required")
		return
	}
	params := map[string]interface{}{}
	if *paramList != "" {
		for _, kv := range strings.Split(*paramList, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				params[parts[0]] = parts[1]
			}
		}
	}

	// load file
	data, err := os.ReadFile(*file)
	if err != nil && !os.IsNotExist(err) {
		fmt.Println(err)
		return
	}
	var entries []plugins.AllowlistEntry
	if len(data) > 0 {
		if err := json.Unmarshal(data, &entries); err != nil {
			fmt.Println(err)
			return
		}
	}
	// find integration
	var entry *plugins.AllowlistEntry
	for i := range entries {
		if entries[i].Integration == *integ {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		entries = append(entries, plugins.AllowlistEntry{Integration: *integ})
		entry = &entries[len(entries)-1]
	}
	// find caller
	var callerCfg *plugins.CallerConfig
	for i := range entry.Callers {
		if entry.Callers[i].ID == *caller {
			callerCfg = &entry.Callers[i]
			break
		}
	}
	if callerCfg == nil {
		entry.Callers = append(entry.Callers, plugins.CallerConfig{ID: *caller})
		callerCfg = &entry.Callers[len(entry.Callers)-1]
	}
	callerCfg.Capabilities = append(callerCfg.Capabilities, plugins.CapabilityConfig{Name: *capName, Params: params})

	out, _ := json.MarshalIndent(entries, "", "    ")
	if err := os.WriteFile(*file, out, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
