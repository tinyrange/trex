// Package imports links the built-in format detectors. Import it for side effects.
package imports

import (
	_ "github.com/tinyrange/trex/archive/ar"
	_ "github.com/tinyrange/trex/archive/bzip2"
	_ "github.com/tinyrange/trex/archive/cab"
	_ "github.com/tinyrange/trex/archive/cfb"
	_ "github.com/tinyrange/trex/archive/gzip"
	_ "github.com/tinyrange/trex/archive/kwaj"
	_ "github.com/tinyrange/trex/archive/sevenzip"
	_ "github.com/tinyrange/trex/archive/sfp"
	_ "github.com/tinyrange/trex/archive/szdd"
	_ "github.com/tinyrange/trex/archive/tar"
	_ "github.com/tinyrange/trex/archive/wim"
	_ "github.com/tinyrange/trex/archive/xz"
	_ "github.com/tinyrange/trex/archive/zip"
	_ "github.com/tinyrange/trex/filesystem/fat"
	_ "github.com/tinyrange/trex/filesystem/gpt"
	_ "github.com/tinyrange/trex/filesystem/iso9660"
	_ "github.com/tinyrange/trex/filesystem/mbr"
	_ "github.com/tinyrange/trex/filesystem/ntfs"
	_ "github.com/tinyrange/trex/filesystem/udf"
	_ "github.com/tinyrange/trex/filesystem/vhdx"
	_ "github.com/tinyrange/trex/installer/installshield"
)
