// Command ember-custom is a thin distribution wrapper that compiles Ember
// together with the local CrowdSec plugin. The blank import triggers the
// plugin's init() which registers it in Ember's global plugin registry
// before ember.Run() starts the TUI.
package main

import (
	"fmt"
	"os"

	"github.com/alexandre-daubois/ember"

	// Side-effect import: registers the CrowdSec plugin via init().
	_ "forgejo.routetohome.renewulff.de/formin/ember-crowdsec/plugin"
)

func main() {
	if err := ember.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
