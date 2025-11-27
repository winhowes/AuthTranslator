package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	yaml "gopkg.in/yaml.v3"

	"github.com/winhowes/AuthTranslator/cmd/allowlist/plugins"
)

var (
	file        = flag.String("file", "allowlist.yaml", "allowlist file")
	yamlMarshal = yaml.Marshal
	writeFile   = os.WriteFile
	exitFunc    = os.Exit
)

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
		fs.Usage()
		return
	}
	params := parseParams(*paramList)

	entries, err := loadAllowlist(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	wantName := strings.ToLower(*integ)
	entryIdx := findIntegration(entries, wantName)
	if entryIdx == -1 {
		entries = append(entries, plugins.AllowlistEntry{Integration: wantName})
		entryIdx = len(entries) - 1
	} else {
		entries[entryIdx].Integration = wantName
	}

	callerIdx := findCaller(entries[entryIdx].Callers, *caller)
	if callerIdx == -1 {
		entries[entryIdx].Callers = append(entries[entryIdx].Callers, plugins.CallerConfig{ID: *caller})
		callerIdx = len(entries[entryIdx].Callers) - 1
	}

	entries[entryIdx].Callers[callerIdx].Capabilities = upsertCapability(entries[entryIdx].Callers[callerIdx].Capabilities, *capName, params)
	saveAllowlist(entries)
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
		fs.Usage()
		return
	}

	entries, err := loadAllowlist(false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	wantName := strings.ToLower(*integ)
	entryIdx := findIntegration(entries, wantName)
	if entryIdx != -1 {
		entries[entryIdx].Integration = wantName
		callerIdx := findCaller(entries[entryIdx].Callers, *caller)
		if callerIdx != -1 {
			entries[entryIdx].Callers[callerIdx].Capabilities = trimCapabilities(entries[entryIdx].Callers[callerIdx].Capabilities, *capName)
			if len(entries[entryIdx].Callers[callerIdx].Capabilities) == 0 {
				entries[entryIdx].Callers = slices.Delete(entries[entryIdx].Callers, callerIdx, callerIdx+1)
			}
			if len(entries[entryIdx].Callers) == 0 {
				entries = slices.Delete(entries, entryIdx, entryIdx+1)
			}
		}
	}

	saveAllowlist(entries)
}

func parseParams(paramList string) map[string]interface{} {
	params := make(map[string]interface{})
	for _, kv := range strings.Split(paramList, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		params[key] = value
	}
	if len(params) == 0 {
		return nil
	}
	return params
}

func loadAllowlist(allowMissing bool) ([]plugins.AllowlistEntry, error) {
	data, err := os.ReadFile(*file)
	if err != nil {
		if allowMissing && os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var entries []plugins.AllowlistEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func findIntegration(entries []plugins.AllowlistEntry, name string) int {
	for i := range entries {
		if strings.ToLower(entries[i].Integration) == name {
			return i
		}
	}
	return -1
}

func findCaller(callers []plugins.CallerConfig, id string) int {
	for i := range callers {
		if callers[i].ID == id {
			return i
		}
	}
	return -1
}

func upsertCapability(caps []plugins.CapabilityConfig, name string, params map[string]interface{}) []plugins.CapabilityConfig {
	for i := range caps {
		if caps[i].Name == name {
			caps[i].Params = params
			return caps
		}
	}
	return append(caps, plugins.CapabilityConfig{Name: name, Params: params})
}

func trimCapabilities(caps []plugins.CapabilityConfig, name string) []plugins.CapabilityConfig {
	trimmed := slices.DeleteFunc(caps, func(cap plugins.CapabilityConfig) bool {
		return cap.Name == name
	})
	for i := range trimmed {
		if len(trimmed[i].Params) == 0 {
			trimmed[i].Params = nil
		}
	}
	return trimmed
}

func saveAllowlist(entries []plugins.AllowlistEntry) {
	out, err := yamlMarshal(entries)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitFunc(1)
	}
	out = bytes.ReplaceAll(out, []byte("params: {}"), []byte("params: null"))

	if err := writeFile(*file, out, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitFunc(1)
	}
}
