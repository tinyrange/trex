module github.com/tinyrange/trex

go 1.25.5

require (
	github.com/therootcompany/xz v1.0.1
	go.starlark.net v0.0.0-20260630144053-529d8e869a14
	golang.org/x/arch v0.29.0
	golang.org/x/sys v0.43.0
	j5.nz/cc v0.0.0
	renvo.dev v0.0.0
)

require (
	github.com/containerd/stargz-snapshotter/estargz v0.18.2 // indirect
	github.com/ebitengine/purego v0.10.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/tinyrange/gowin v0.0.0-20260809233042-3f02e7d42a2d // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/vbatts/tar-split v0.12.2 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
)

replace renvo.dev => ./renvo

replace j5.nz/cc => ./cc
