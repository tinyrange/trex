package starlarkfrontend

import "strings"

func webDisplayURL(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "http://localhost" + addr + "/"
	}
	return "http://" + addr + "/"
}
