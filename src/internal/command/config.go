package command

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsimple"
)

// serverConfig is the parsed HCL/JSON server configuration. Unknown attributes
// and blocks (e.g. seal, telemetry, api_addr) are tolerated via Remain so that
// Vault-shaped configs load without error; unsupported features are simply
// ignored in Phase 1.
type serverConfig struct {
	Storage  *storageStanza  `hcl:"storage,block"`
	Listener *listenerStanza `hcl:"listener,block"`
	UI       bool            `hcl:"ui,optional"`
	Remain   hcl.Body        `hcl:",remain"`
}

type storageStanza struct {
	Type   string   `hcl:"type,label"`
	Path   string   `hcl:"path,optional"`
	Remain hcl.Body `hcl:",remain"`
}

type listenerStanza struct {
	Type       string   `hcl:"type,label"`
	Address    string   `hcl:"address,optional"`
	TLSDisable bool     `hcl:"tls_disable,optional"`
	Remain     hcl.Body `hcl:",remain"`
}

func loadConfig(path string) (*serverConfig, error) {
	var cfg serverConfig
	if err := hclsimple.DecodeFile(path, nil, &cfg); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	if cfg.Storage == nil {
		return nil, fmt.Errorf("config %q: a storage stanza is required", path)
	}
	return &cfg, nil
}
