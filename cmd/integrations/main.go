package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	yaml "gopkg.in/yaml.v3"

	"github.com/winhowes/AuthTranslator/cmd/integrations/plugins"
)

var file = flag.String("file", "config.yaml", "config file")

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
		os.Exit(1)
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
			os.Exit(1)
		}
		deleteIntegration(args[0])
		return
	}
	if cmd == "update" {
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "update requires plugin name")
			os.Exit(1)
		}
		builder := plugins.Get(args[0])
		if builder == nil {
			fmt.Fprintf(os.Stderr, "unknown plugin %s\n", args[0])
			os.Exit(1)
		}
		integ, err := builder(args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		updateIntegration(integ)
		return
	}

	builder := plugins.Get(cmd)
	if builder == nil {
		fmt.Fprintf(os.Stderr, "unknown plugin %s\n", cmd)
		os.Exit(1)
	}
	integ, err := builder(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	addIntegration(integ)
}

func addIntegration(i plugins.Integration) {
	i.Name = strings.ToLower(i.Name)
	list, err := readConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, existing := range list {
		if strings.EqualFold(existing.Name, i.Name) {
			fmt.Fprintf(os.Stderr, "integration %s already exists\n", i.Name)
			os.Exit(1)
		}
	}
	list = append(list, i)
	if err := writeConfig(list); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("integration added")
}

func updateIntegration(i plugins.Integration) {
	i.Name = strings.ToLower(i.Name)
	list, err := readConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	found := false
	for idx := range list {
		if strings.EqualFold(list[idx].Name, i.Name) {
			list[idx] = i
			found = true
			break
		}
	}
	if !found {
		list = append(list, i)
	}
	if err := writeConfig(list); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("integration updated")
}

func deleteIntegration(name string) {
	name = strings.ToLower(name)
	list, err := readConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for idx := range list {
		if strings.EqualFold(list[idx].Name, name) {
			list = append(list[:idx], list[idx+1:]...)
			break
		}
	}
	if err := writeConfig(list); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("integration deleted")
}

func listIntegrations() {
	list, err := readConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, i := range list {
		fmt.Println(i.Name)
	}
}

func readConfig() ([]plugins.Integration, error) {
	data, err := os.ReadFile(*file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg struct {
		Integrations []plugins.Integration `yaml:"integrations"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.Integrations, nil
}

func writeConfig(integrations []plugins.Integration) error {
	cfg := struct {
		Integrations []plugins.Integration `yaml:"integrations"`
	}{integrations}
	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(*file, out, 0644)
}
