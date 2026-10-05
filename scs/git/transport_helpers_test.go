package gitstore

import (
	"context"
	scsnative "github.com/tinyrange/trex/scs/native"
	"github.com/tinyrange/trex/scs/repo"
	"io"
)

func cloneFixture(ctx context.Context, r *repo.Repository, url string, opt Options) (Report, error) {
	t, e := scsnative.GitTransport(url)
	if e != nil {
		return Report{}, e
	}
	opt.Transport = t
	return Clone(ctx, r, url, opt)
}
func receiveFixture(ctx context.Context, url string, w io.Writer, opt Options) (Download, error) {
	t, e := scsnative.GitTransport(url)
	if e != nil {
		return Download{}, e
	}
	opt.Transport = t
	return ReceivePack(ctx, url, w, opt)
}
