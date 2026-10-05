module github.com/tinyrange/trex

go 1.25.5

require (
	github.com/benhoyt/goawk v1.32.0
	github.com/go-git/go-git/v5 v5.19.2
	github.com/klauspost/compress v1.18.6
	github.com/pjbgf/sha1cd v0.6.0
	github.com/therootcompany/xz v1.0.1
	github.com/tinyrange/gowin v0.0.0-20260809233042-3f02e7d42a2d
	github.com/ulikunitz/xz v0.5.15
	go.starlark.net v0.0.0-20260630144053-529d8e869a14
	golang.org/x/arch v0.29.0
	golang.org/x/sys v0.46.0
	golang.org/x/text v0.39.0
	j5.nz/cc v0.0.0
	mvdan.cc/sh/v3 v3.12.0
	renvo.dev v0.0.0
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.18.2 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/ebitengine/purego v0.10.0 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.0 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/vbatts/tar-split v0.12.2 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)

replace renvo.dev => ./renvo

replace j5.nz/cc => ./cc
