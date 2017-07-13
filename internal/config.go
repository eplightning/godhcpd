package internal

import (
	"fmt"

	"os"

	"sync"

	"github.com/BurntSushi/toml"
)

type PoolConfig struct {
	Interfaces []string
	Network    string
	Start      int
	End        int
	Algorithm  string
	Lifetime   string
}

type ConfigFile struct {
	Pools map[string]PoolConfig
}

var GlobalConfig ConfigFile
var once sync.Once

func getDefaultConfig() ConfigFile {
	return ConfigFile{
		Pools: map[string]PoolConfig{
			"default": PoolConfig{
				Interfaces: []string{
					"vboxnet0",
				},
				Network:   "192.168.99.0/24",
				Start:     2,
				End:       99,
				Algorithm: "random",
				Lifetime:  "24h",
			},
		},
	}
}

func LoadGlobalConfig(file string) {
	GlobalConfig = LoadConfig(file)
}

func LoadConfig(file string) ConfigFile {
	var conf ConfigFile

	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Println("Configuration file not found, using defaults ...")
		return getDefaultConfig()
	}

	if _, err := toml.DecodeFile(file, &conf); err != nil {
		fmt.Println("Unable to load configuration file, using defaults ...", err)
		return getDefaultConfig()
	}

	return conf
}
