package native

import (
	"fmt"
	"github.com/go-git/go-git/v5/plumbing/transport"
	gitnet "github.com/go-git/go-git/v5/plumbing/transport/git"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

// GitTransport selects only native Go network backends. No command-based local
// Git transport is installed or acquired by this adapter.
func GitTransport(url string) (transport.Transport, error) {
	ep, err := transport.NewEndpoint(url)
	if err != nil {
		return nil, err
	}
	switch ep.Protocol {
	case "http", "https":
		return githttp.DefaultClient, nil
	case "git":
		return gitnet.DefaultClient, nil
	case "ssh":
		return gitssh.DefaultClient, nil
	default:
		return nil, fmt.Errorf("unsupported Git transport %q", ep.Protocol)
	}
}
