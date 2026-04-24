package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"os"
	"sort"
	"strings"

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
	list := plugins.List()
	integrations := make([]string, 0, len(list))
	for integ := range list {
		integrations = append(integrations, integ)
	}
	sort.Strings(integrations)
	for _, integ := range integrations {
		caps := list[integ]
		fmt.Println(integ + ":")
		names := make([]string, 0, len(caps))
		for name := range caps {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			spec := caps[name]
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
	params, err := parseParams(*paramList)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	wantName := strings.ToLower(*integ)
	if err := plugins.ValidateCapability(wantName, plugins.CapabilityConfig{Name: *capName, Params: params}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
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
	replaced := false
	for i := range callerCfg.Capabilities {
		if callerCfg.Capabilities[i].Name == *capName {
			callerCfg.Capabilities[i].Params = params
			replaced = true
			break
		}
	}
	if !replaced {
		callerCfg.Capabilities = append(callerCfg.Capabilities, plugins.CapabilityConfig{Name: *capName, Params: params})
	}

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

func parseParams(paramList string) (map[string]interface{}, error) {
	if strings.TrimSpace(paramList) == "" {
		return nil, nil
	}
	params := make(map[string]interface{})
	items, err := splitParamList(paramList)
	if err != nil {
		return nil, err
	}
	for _, kv := range items {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("invalid param %q, expected key=value", kv)
		}
		value, err := parseParamValue(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid value for param %s: %w", strings.TrimSpace(parts[0]), err)
		}
		params[strings.TrimSpace(parts[0])] = value
	}
	return params, nil
}

func splitParamList(paramList string) ([]string, error) {
	var parts []string
	start := 0
	depth := 0
	inQuote := false
	escaped := false
	for i, r := range paramList {
		if inQuote {
			if escaped {
				escaped = false
				continue
			}
			switch r {
			case '\\':
				escaped = true
			case '"':
				inQuote = false
			}
			continue
		}
		switch r {
		case '"':
			inQuote = true
		case '[', '{':
			depth++
		case ']', '}':
			if depth == 0 {
				return nil, fmt.Errorf("invalid params: unmatched %q", r)
			}
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, paramList[start:i])
				start = i + 1
			}
		}
	}
	if inQuote {
		return nil, fmt.Errorf("invalid params: unterminated quoted value")
	}
	if depth != 0 {
		return nil, fmt.Errorf("invalid params: unmatched bracket or brace")
	}
	parts = append(parts, paramList[start:])
	return parts, nil
}

func parseParamValue(raw string) (interface{}, error) {
	if raw == "" {
		return "", nil
	}
	switch raw[0] {
	case '[', '{', '"':
		var v interface{}
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, err
		}
		return v, nil
	}
	switch raw {
	case "null":
		return nil, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return raw, nil
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
		fs.Usage()
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
