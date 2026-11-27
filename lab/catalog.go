package lab

import (
	"fmt"
)

var ethernetPort = Port{ID: "lan", Label: "NIC 1", Kind: "ethernet"}
var linuxEthernetPort = Port{ID: "lan", Label: "eth0", Kind: "ethernet"}

func disk(key, label, hint string) Media {
	return Media{Key: key, Label: label, Hint: hint, Kind: "file"}
}

func memory(defaultMiB, minMiB, maxMiB int) Field {
	return Field{Key: "memoryMiB", Label: "Memory (MiB)", Group: "General", Kind: "number", Default: defaultMiB, Min: minMiB, Max: maxMiB,
		Impact: "rebuild", Help: "Changing RAM replaces this guest and its temporary disk."}
}

func address() Field {
	return Field{Key: "address", Label: "Static IPv4 address", Group: "Network", Kind: "string", Default: "", Impact: "rebuild",
		Help: "Optional address on the isolated Ethernet segment. Use CIDR notation, for example 10.20.0.30/24."}
}

// Catalog returns the built-in Trex lab recipes.
func Catalog() []Recipe {
	var recipes []Recipe
	newRecipe := func(id, title, family, group, description, fn string, fields []Field, media []Media, ports []Port) {
		recipe := Recipe{ID: id, Title: title, Family: family, Group: group, Description: description, Function: fn,
			Fields: append([]Field{}, fields...), Media: append([]Media{}, media...), Ports: append([]Port{}, ports...)}
		switch fn {
		case "alpine", "live_linux":
			recipe.Module, recipe.Backend = "//_trex_lab:linux.star", "cc"
		case "dos622", "win101":
			recipe.Module, recipe.Backend = "//_trex_lab:legacy.star", "cc"
		case "indy":
			recipe.Module, recipe.Backend = "//_trex_lab:irix.star", "ip24"
		}
		recipes = append(recipes, recipe)
	}
	switchPorts := make([]Port, 0, switchPortLimit)
	for number := 1; number <= switchPortLimit; number++ {
		switchPorts = append(switchPorts, Port{ID: switchPortID(number), Label: fmt.Sprintf("Port %d", number), Kind: "ethernet"})
	}
	newRecipe("switch", "Isolated Ethernet switch", "Infrastructure", "Networking", "Connect guests on a private layer-2 network.", "switch", nil, nil, switchPorts)
	newRecipe("router", "Router", "Infrastructure", "Networking", "Provide DHCP and local DNS on an isolated switch.", "router", []Field{
		{Key: "routerAddress", Label: "LAN address", Group: "Network", Kind: "string", Default: "10.20.0.1/24", Impact: "rebuild",
			Help: "IPv4 address of the router with its subnet prefix."},
		{Key: "dhcp", Label: "DHCP server", Group: "Network", Kind: "boolean", Default: true, Impact: "rebuild"},
		{Key: "dhcpStart", Label: "First lease address", Group: "Network", Kind: "string", Default: "10.20.0.100", Impact: "rebuild"},
		{Key: "dhcpEnd", Label: "Last lease address", Group: "Network", Kind: "string", Default: "10.20.0.199", Impact: "rebuild"},
		{Key: "dhcpMinutes", Label: "Lease length (minutes)", Group: "Network", Kind: "number", Default: 1440, Min: 1, Max: 10080, Impact: "rebuild"},
		{Key: "dhcpDNS", Label: "DHCP DNS override", Group: "Network", Kind: "string", Default: "", Impact: "rebuild",
			Help: "Leave blank to use the router's DNS server for lab.test names."},
	}, nil, []Port{{ID: "lan", Label: "LAN", Kind: "ethernet"}})
	var dos []Media
	for n := 1; n <= 3; n++ {
		dos = append(dos, disk(fmt.Sprintf("dos%d", n), fmt.Sprintf("MS-DOS 6.22 disk %d", n), "Original floppy image"))
	}
	newRecipe("dos622", "MS-DOS 6.22", "DOS / Legacy", "MS-DOS", "Build and boot an installed system from original floppies.", "dos622",
		[]Field{memory(16, 16, 64)}, dos, nil)
	recipes[len(recipes)-1].ReleaseYear = 1994
	win101 := append([]Media{}, dos...)
	for _, section := range []string{"setup", "build", "utilities", "applications", "write"} {
		win101 = append(win101, disk(section, "Windows 1.01 "+section+" disk", "Original floppy image"))
	}
	newRecipe("win101", "Windows 1.01", "Windows", "Windows 1.x–3.x", "Build and boot an installed system from original floppies.", "win101",
		[]Field{memory(16, 16, 64)}, win101, nil)
	recipes[len(recipes)-1].ReleaseYear = 1985
	newRecipe("alpine", "Alpine Linux 3.22", "Linux", "Linux", "Build and boot an Alpine shell from selected packages in memory.", "alpine",
		[]Field{memory(512, 128, 1024), address(), {Key: "packages", Label: "Alpine packages", Group: "Software", Kind: "alpine-packages",
			Default: []string{}, Impact: "rebuild"}}, nil, []Port{linuxEthernetPort})
	recipes[len(recipes)-1].ReleaseYear = 2025
	newRecipe("web-server", "Web Server", "Infrastructure", "Services", "Serve configurable HTTP responses on the lab network.", "web_server",
		[]Field{address(), {Key: "port", Label: "HTTP port", Group: "Network", Kind: "number", Default: 80, Min: 1, Max: 65535, Impact: "rebuild"},
			{Key: "content", Label: "Website content", Group: "HTTP", Kind: "select", Default: "example",
				Impact: "rebuild", Options: []Option{{Value: "example", Label: "Example website"}, {Value: "html", Label: "HTML file"}, {Value: "routes", Label: "Routes only"}}},
			{Key: "routes", Label: "HTTP routes (JSON)", Group: "HTTP", Kind: "multiline", Default: "", Max: maxWebRoutesJSON, Impact: "rebuild",
				Help: "Add or override responses with an array of objects containing method, path, status, headers, and body."}},
		[]Media{{Key: "document", Label: "Website HTML file", Hint: "A self-contained HTML page of up to 4 MiB", Kind: "file", When: "content", Equals: "html"}},
		[]Port{ethernetPort})
	newRecipe("debian-live", "Debian Live", "Linux", "Linux", "Boot Debian’s original x64 live environment on the lab network.", "live_linux",
		[]Field{memory(1536, 768, 2048)}, []Media{disk("system", "Debian amd64 Live ISO", "Original Debian Live ISO, with /live/vmlinuz and /live/initrd.img")}, []Port{ethernetPort})
	newRecipe("ubuntu-live", "Ubuntu Desktop Live", "Linux", "Linux", "Boot Ubuntu's x64 live environment.", "live_linux",
		[]Field{memory(2048, 1024, 2048)}, []Media{disk("system", "Ubuntu Desktop amd64 ISO", "Original Ubuntu Desktop ISO, with /casper/vmlinuz and /casper/initrd")}, []Port{ethernetPort})
	newRecipe("fedora-rescue", "Fedora Server Rescue", "Linux", "Linux", "Boot the original Fedora Server rescue environment from its installation media.", "live_linux",
		[]Field{memory(2048, 1024, 2048)}, []Media{disk("system", "Fedora Server amd64 ISO", "Original Fedora Server DVD or netinstall ISO")}, []Port{ethernetPort})
	irixMedia := []Media{
		disk("foundation1", "IRIX 6.5 Foundation 1", "Original SGI CD in a .7z archive"),
		disk("foundation2", "IRIX 6.5 Foundation 2", "Original SGI CD in a .7z archive"),
		disk("overlay1", "IRIX 6.5.22 Overlay 1", "Original SGI CD in a .7z archive"),
		disk("overlay2", "IRIX 6.5.22 Overlay 2", "Original SGI CD in a .7z archive"),
		disk("overlay3", "IRIX 6.5.22 Overlay 3", "Original SGI CD in a .7z archive"),
		disk("applications", "IRIX 6.5.22 Applications (November 2003)", "Original SGI CD in a .7z archive"),
		disk("system", "Installed IRIX 6.5.22 disk", "SGI Indy system disk in CHD format"),
	}
	for i := range irixMedia {
		irixMedia[i].When, irixMedia[i].Equals = "source", "discs"
		if irixMedia[i].Key == "system" {
			irixMedia[i].Equals = "installed"
		}
	}
	newRecipe("irix-indy", "IRIX 6.5.22 (SGI Indy)", "UNIX", "SGI", "Boot the IRIX Interactive Desktop on a Newport Indy.", "indy",
		[]Field{{Key: "source", Label: "Boot media", Group: "General", Kind: "select", Default: "discs", Impact: "rebuild",
			Options: []Option{{Value: "discs", Label: "Original installation discs"}, {Value: "installed", Label: "Installed CHD disk"}}}}, irixMedia, nil)
	recipes[len(recipes)-1].ReleaseYear = 2003
	return recipes
}
