package shell

import (
	"fmt"
	"strings"
	"time"
)

// date deliberately uses no host timezone database or environment. Unsupported
// zones and directives are capability errors, not misleading command results.
func Date(in Invocation, clock func() time.Time) (int, error) {
	args := in.Args[1:]
	utc := false
	if len(args) > 0 && (args[0] == "-u" || args[0] == "--utc" || args[0] == "--universal") {
		utc = true
		args = args[1:]
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	zone := in.Env["TZ"]
	if !utc && zone != "" && zone != "UTC" && zone != "GMT" && zone != "UTC0" && zone != "GMT0" {
		return 0, &UnsupportedError{Feature: "date timezone " + zone}
	}
	format := "%a %b %e %H:%M:%S UTC %Y"
	if len(args) > 1 || len(args) == 1 && !strings.HasPrefix(args[0], "+") {
		return 0, &UnsupportedError{Feature: "date arguments"}
	}
	if len(args) == 1 {
		format = args[0][1:]
	}
	now := time.Now
	if clock != nil {
		now = clock
	}
	value, err := formatDate(now().UTC(), format)
	if err != nil {
		return 0, err
	}
	_, err = fmt.Fprintln(in.Stdout, value)
	return 0, err
}
func formatDate(t time.Time, format string) (string, error) {
	var out strings.Builder
	layouts := map[byte]string{'Y': "2006", 'y': "06", 'm': "01", 'd': "02", 'e': "_2", 'H': "15", 'M': "04", 'S': "05", 'a': "Mon", 'A': "Monday", 'b': "Jan", 'B': "January", 'F': "2006-01-02", 'T': "15:04:05", 'z': "-0700", 'Z': "MST"}
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			out.WriteByte(format[i])
			continue
		}
		i++
		if i == len(format) {
			return "", &UnsupportedError{Feature: "date trailing %"}
		}
		switch format[i] {
		case '%':
			out.WriteByte('%')
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case 'j':
			fmt.Fprintf(&out, "%03d", t.YearDay())
		case 's':
			fmt.Fprintf(&out, "%d", t.Unix())
		case 'w':
			fmt.Fprintf(&out, "%d", t.Weekday())
		case 'u':
			d := int(t.Weekday())
			if d == 0 {
				d = 7
			}
			fmt.Fprintf(&out, "%d", d)
		default:
			layout, ok := layouts[format[i]]
			if !ok {
				return "", &UnsupportedError{Feature: fmt.Sprintf("date directive %%%c", format[i])}
			}
			out.WriteString(t.Format(layout))
		}
	}
	return out.String(), nil
}
