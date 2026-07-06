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
	Seal     *sealStanza     `hcl:"seal,block"`
	UI       bool            `hcl:"ui,optional"`
	Remain   hcl.Body        `hcl:",remain"`
}

// sealStanza configures an auto-unseal mechanism, e.g.
//
//	seal "transit" {
//	  address   = "https://seal-source:8200"
//	  token     = "..."
//	  mount_path = "transit"
//	  key_name   = "autounseal"
//	}
type sealStanza struct {
	Type          string   `hcl:"type,label"`
	Address       string   `hcl:"address,optional"`
	Token         string   `hcl:"token,optional"`
	MountPath     string   `hcl:"mount_path,optional"`
	KeyName       string   `hcl:"key_name,optional"`
	TLSSkipVerify bool     `hcl:"tls_skip_verify,optional"`
	Remain        hcl.Body `hcl:",remain"`
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
