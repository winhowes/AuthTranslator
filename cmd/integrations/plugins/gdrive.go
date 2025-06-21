package plugins

import "flag"

// GDrive returns an Integration configured for the Google Drive API.
func GDrive(name string) Integration {
	return Integration{
		Name:         name,
		Destination:  "https://www.googleapis.com/drive/v3",
		InRateLimit:  100,
		OutRateLimit: 100,
		OutgoingAuth: []AuthPluginConfig{{
			Type:   "gcp_token",
			Params: map[string]interface{}{},
		}},
	}
}

func init() { Register("gdrive", gdriveBuilder) }

func gdriveBuilder(args []string) (Integration, error) {
	fs := flag.NewFlagSet("gdrive", flag.ContinueOnError)
	name := fs.String("name", "gdrive", "integration name")
	if err := fs.Parse(args); err != nil {
		return Integration{}, err
	}
	return GDrive(*name), nil
}
