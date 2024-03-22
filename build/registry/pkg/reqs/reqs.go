package reqs

import (
	"fmt"
	"os"
	"strings"

	falcoctlOci "github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/plugin-sdk-go/pkg/loader"
	"github.com/falcosecurity/plugins/build/registry/pkg/common"
	"github.com/spf13/cobra"
)

type options struct {
	artifactType falcoctlOci.ArtifactType
}

func NewReqsCmd() *cobra.Command {
	opt := options{}

	cmd := &cobra.Command{
		Use:                   "reqs file [flags]",
		Short:                 "Extracts requirements from a given artifact",
		Args:                  cobra.ExactArgs(1),
		SilenceErrors:         true,
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return opt.Run(args)
		},
	}

	flags := cmd.Flags()
	flags.Var(&opt.artifactType, "type", `type of artifact. Allowed values "plugin"`)

	return cmd
}

func (o *options) Run(args []string) error {
	var plugin *loader.Plugin
	var err error

	if o.artifactType != falcoctlOci.Plugin {
		return fmt.Errorf("only artifacts of type %q are supported", falcoctlOci.Plugin)
	}

	// Create temp dir.
	tmpDir, err := os.MkdirTemp("", "registry-reqs-")
	if err != nil {
		return fmt.Errorf("unable to create temporary dir while preparing to extract artifact %q: %v", args[0], err)
	}

	defer os.RemoveAll(tmpDir)

	files, err := common.ExtractTarGz(args[0], tmpDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		// skip files that are not a shared library such as README files.
		if !strings.HasSuffix(file, ".so") {
			continue
		}

		// Get the requirement for the given file.
		plugin, err = loader.NewPlugin(file)
		if err != nil {
			return fmt.Errorf("unable to open plugin %q: %w", file, err)
		}
	}

	if plugin == nil {
		return fmt.Errorf("no shared object found in %s", args[0])
	}

	fmt.Printf("%s:%s\n", common.PluginAPIVersion, plugin.Info().RequiredAPIVersion)

	return nil
}
