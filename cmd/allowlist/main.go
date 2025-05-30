package main

import (
	"bytes"
	"flag"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"os"
	"strings"

	"github.com/winhowes/AuthTranslator/cmd/allowlist/plugins"
)

var file = flag.String("file", "allowlist.yaml", "allowlist file")

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `Usage: allowlist [options] <command>\n\n`)
	fmt.Fprintf(flag.CommandLine.Output(), "Commands:\n  list   show plugin capabilities\n  add    update the allowlist\n  remove delete an entry from the allowlist\n\nOptions:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}
	switch flag.Arg(0) {
	case "list":
		listCaps()
	case "add":
		addEntry(flag.Args()[1:])
	case "remove":
		removeEntry(flag.Args()[1:])
	default:
		usage()
		os.Exit(1)
	}
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
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: allowlist add [flags]\n\n")
		fs.PrintDefaults()
	}
	integ := fs.String("integration", "", "integration name")
	caller := fs.String("caller", "", "caller id")
	capName := fs.String("capability", "", "capability name")
	paramList := fs.String("params", "", "comma separated key=value")
	fs.Parse(args)
	if *integ == "" || *caller == "" || *capName == "" {
		fmt.Println("-integration, -caller and -capability required")
		return
	}
	var params map[string]interface{}
	if *paramList != "" {
		params = make(map[string]interface{})
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
		fmt.Fprintln(os.Stderr, err)
		return
	}
	var entries []plugins.AllowlistEntry
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &entries); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
	// find integration
	wantName := strings.ToLower(*integ)
	var entry *plugins.AllowlistEntry
	for i := range entries {
		if strings.ToLower(entries[i].Integration) == wantName {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		entries = append(entries, plugins.AllowlistEntry{Integration: wantName})
		entry = &entries[len(entries)-1]
	} else {
		entry.Integration = wantName
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

	out, err := yaml.Marshal(entries)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out = bytes.ReplaceAll(out, []byte("params: {}"), []byte("params: null"))

	if err := os.WriteFile(*file, out, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func removeEntry(args []string) {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: allowlist remove [flags]\n\n")
		fs.PrintDefaults()
	}
	integ := fs.String("integration", "", "integration name")
	caller := fs.String("caller", "", "caller id")
	capName := fs.String("capability", "", "capability name")
	fs.Parse(args)

	if *integ == "" || *caller == "" || *capName == "" {
		fmt.Println("-integration, -caller and -capability required")
		return
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	wantName := strings.ToLower(*integ)
	for ei := range entries {
		if strings.ToLower(entries[ei].Integration) != wantName {
			continue
		}
		entries[ei].Integration = wantName
		for ci := range entries[ei].Callers {
			if entries[ei].Callers[ci].ID != *caller {
				continue
			}
			caps := entries[ei].Callers[ci].Capabilities
			for i := 0; i < len(caps); i++ {
				if caps[i].Name == *capName {
					caps = append(caps[:i], caps[i+1:]...)
					i--
					continue
				}
			}
			if len(caps) == 0 {
				entries[ei].Callers = append(entries[ei].Callers[:ci], entries[ei].Callers[ci+1:]...)
			} else {
				for i := range caps {
					if len(caps[i].Params) == 0 {
						caps[i].Params = nil
					}
				}
				entries[ei].Callers[ci].Capabilities = caps
			}
			break
		}
		if len(entries[ei].Callers) == 0 {
			entries = append(entries[:ei], entries[ei+1:]...)
		}
		break
	}

	out, err := yaml.Marshal(entries)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out = bytes.ReplaceAll(out, []byte("params: {}"), []byte("params: null"))
	if err := os.WriteFile(*file, out, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
