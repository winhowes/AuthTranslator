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
	params := parseParams(*paramList)

	entries, err := loadEntries(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	entries, entry := upsertIntegration(entries, *integ)
	callerCfg := upsertCaller(entry, *caller)
	upsertCapability(callerCfg, *capName, params)

	if err := writeEntries(entries); err != nil {
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

	entries, err := loadEntries(false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	entries = normalizeEntries(entries)
	entries = removeCapability(entries, *integ, *caller, *capName)

	if err := writeEntries(entries); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseParams(paramList string) map[string]interface{} {
	if paramList == "" {
		return nil
	}
	params := make(map[string]interface{})
	for _, kv := range strings.Split(paramList, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		key, value, found := strings.Cut(kv, "=")
		if !found {
			continue
		}
		params[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return params
}

func loadEntries(allowMissing bool) ([]plugins.AllowlistEntry, error) {
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

func writeEntries(entries []plugins.AllowlistEntry) error {
	out, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	out = bytes.ReplaceAll(out, []byte("params: {}"), []byte("params: null"))
	return os.WriteFile(*file, out, 0644)
}

func upsertIntegration(entries []plugins.AllowlistEntry, name string) ([]plugins.AllowlistEntry, *plugins.AllowlistEntry) {
	normalized := strings.ToLower(name)
	idx := slices.IndexFunc(entries, func(entry plugins.AllowlistEntry) bool {
		return strings.EqualFold(entry.Integration, normalized)
	})
	if idx == -1 {
		entries = append(entries, plugins.AllowlistEntry{Integration: normalized})
		return entries, &entries[len(entries)-1]
	}
	entries[idx].Integration = normalized
	return entries, &entries[idx]
}

func upsertCaller(entry *plugins.AllowlistEntry, caller string) *plugins.CallerConfig {
	idx := slices.IndexFunc(entry.Callers, func(cfg plugins.CallerConfig) bool {
		return cfg.ID == caller
	})
	if idx == -1 {
		entry.Callers = append(entry.Callers, plugins.CallerConfig{ID: caller})
		return &entry.Callers[len(entry.Callers)-1]
	}
	return &entry.Callers[idx]
}

func upsertCapability(caller *plugins.CallerConfig, name string, params map[string]interface{}) {
	idx := slices.IndexFunc(caller.Capabilities, func(cap plugins.CapabilityConfig) bool {
		return cap.Name == name
	})
	if idx == -1 {
		caller.Capabilities = append(caller.Capabilities, plugins.CapabilityConfig{Name: name, Params: params})
		return
	}
	caller.Capabilities[idx].Params = params
}

func normalizeEntries(entries []plugins.AllowlistEntry) []plugins.AllowlistEntry {
	for i := range entries {
		entries[i].Integration = strings.ToLower(entries[i].Integration)
	}
	return entries
}

func removeCapability(entries []plugins.AllowlistEntry, integration, caller, capName string) []plugins.AllowlistEntry {
	idx := slices.IndexFunc(entries, func(entry plugins.AllowlistEntry) bool {
		return strings.EqualFold(entry.Integration, integration)
	})
	if idx == -1 {
		return entries
	}

	entry := &entries[idx]
	callerIdx := slices.IndexFunc(entry.Callers, func(cfg plugins.CallerConfig) bool {
		return cfg.ID == caller
	})
	if callerIdx == -1 {
		return entries
	}

	caps := entry.Callers[callerIdx].Capabilities
	capRemoved := false
	caps = slices.DeleteFunc(caps, func(cap plugins.CapabilityConfig) bool {
		if cap.Name == capName {
			capRemoved = true
			return true
		}
		if len(cap.Params) == 0 {
			cap.Params = nil
		}
		return false
	})

	if len(caps) == 0 {
		entry.Callers = append(entry.Callers[:callerIdx], entry.Callers[callerIdx+1:]...)
	} else {
		entry.Callers[callerIdx].Capabilities = caps
	}

	if len(entry.Callers) == 0 {
		entries = append(entries[:idx], entries[idx+1:]...)
	} else if !capRemoved {
		entries[idx] = *entry
	}

	return entries
}
