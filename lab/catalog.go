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
		case "alpine":
			recipe.Module, recipe.Backend = "//_trex_lab:linux.star", "cc"
		case "live_linux":
			recipe.Module, recipe.Backend, recipe.AbsolutePointer = "//_trex_lab:linux.star", "qemu", true
		case "dos622", "win101":
			recipe.Module, recipe.Backend = "//_trex_lab:legacy.star", "cc"
		}
		recipes = append(recipes, recipe)
	}
	switchPorts := make([]Port, 0, switchPortLimit)
	for number := 1; number <= switchPortLimit; number++ {
		switchPorts = append(switchPorts, Port{ID: switchPortID(number), Label: fmt.Sprintf("Port %d", number), Kind: "ethernet"})
	}
	newRecipe("switch", "Isolated Ethernet switch", "Infrastructure", "Networking", "Connect guests on a private layer-2 network.", "switch", nil, nil, switchPorts)
	newRecipe("router", "Router", "Infrastructure", "Networking", "Provide IPv4 addresses on an isolated switch.", "router", []Field{
		{Key: "routerAddress", Label: "LAN address", Group: "Network", Kind: "string", Default: "10.20.0.1/24", Impact: "rebuild",
			Help: "IPv4 address of the router with its subnet prefix."},
		{Key: "dhcp", Label: "DHCP server", Group: "Network", Kind: "boolean", Default: true, Impact: "rebuild"},
		{Key: "dhcpStart", Label: "First lease address", Group: "Network", Kind: "string", Default: "10.20.0.100", Impact: "rebuild"},
		{Key: "dhcpEnd", Label: "Last lease address", Group: "Network", Kind: "string", Default: "10.20.0.199", Impact: "rebuild"},
		{Key: "dhcpMinutes", Label: "Lease length (minutes)", Group: "Network", Kind: "number", Default: 1440, Min: 1, Max: 10080, Impact: "rebuild"},
		{Key: "dhcpDNS", Label: "DNS server (optional)", Group: "Network", Kind: "string", Default: "", Impact: "rebuild"},
	}, nil, []Port{{ID: "lan", Label: "LAN", Kind: "ethernet"}})
	var dos []Media
	for n := 1; n <= 3; n++ {
		dos = append(dos, disk(fmt.Sprintf("dos%d", n), fmt.Sprintf("MS-DOS 6.22 disk %d", n), "Original floppy image"))
	}
	newRecipe("dos622", "MS-DOS 6.22", "DOS / Legacy", "MS-DOS", "Build and boot an installed system from original floppies.", "dos622",
		[]Field{memory(16, 16, 64)}, dos, nil)
	win101 := append([]Media{}, dos...)
	for _, section := range []string{"setup", "build", "utilities", "applications", "write"} {
		win101 = append(win101, disk(section, "Windows 1.01 "+section+" disk", "Original floppy image"))
	}
	newRecipe("win101", "Windows 1.01", "Windows", "Windows 1.x–3.x", "Build and boot an installed system from original floppies.", "win101",
		[]Field{memory(16, 16, 64)}, win101, nil)
	newRecipe("alpine", "Alpine Linux", "Linux", "Linux", "Boot an Alpine shell from pinned packages in memory.", "alpine",
		[]Field{memory(512, 128, 1024), address()}, nil, []Port{linuxEthernetPort})
	newRecipe("debian-live", "Debian Live", "Linux", "Linux", "Boot Debian’s original x64 live environment on the lab network.", "live_linux",
		[]Field{memory(1536, 768, 2048)}, []Media{disk("system", "Debian amd64 Live ISO", "Original Debian Live ISO, with /live/vmlinuz and /live/initrd.img")}, []Port{ethernetPort})
	newRecipe("ubuntu-live", "Ubuntu Desktop Live", "Linux", "Linux", "Boot Ubuntu's x64 live environment.", "live_linux",
		[]Field{memory(2048, 1024, 2048)}, []Media{disk("system", "Ubuntu Desktop amd64 ISO", "Original Ubuntu Desktop ISO, with /casper/vmlinuz and /casper/initrd")}, []Port{ethernetPort})
	newRecipe("fedora-rescue", "Fedora Server Rescue", "Linux", "Linux", "Boot the original Fedora Server rescue environment from its installation media.", "live_linux",
		[]Field{memory(2048, 1024, 2048)}, []Media{disk("system", "Fedora Server amd64 ISO", "Original Fedora Server DVD or netinstall ISO")}, []Port{ethernetPort})
	return recipes
}
