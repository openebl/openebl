package config

import (
	"os"
	"strings"
	"text/template"

	"gopkg.in/yaml.v2"
)

// FromFile read and parse config from given path and apply environment on it
func FromFile(filePath string, cfg interface{}) error {
	envMap := make(map[string]string)
	for _, envStr := range os.Environ() {
		pair := strings.SplitN(envStr, "=", 2)
		envMap[pair[0]] = pair[1]
	}

	t, err := template.ParseFiles(filePath)
	if err != nil {
		return err
	}
	strWriter := &strings.Builder{}
	err = t.Execute(strWriter, envMap)
	if err != nil {
		return err
	}

	content := os.ExpandEnv(strWriter.String())
	err = yaml.Unmarshal([]byte(content), cfg)
	return err
}
