// Package normalize turns "almost-raw" banner text into a canonical byte form.
//
// Real-world scanner dumps are frequently not clean JSON: NUL bytes and other
// control characters are often represented as the literal four characters
// `\x00` rather than a real 0x00 byte. Normalizing here keeps the matching
// rules simple and independent of the input encoding quirks.
package normalize

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

var (
	hexEscape      = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	jsonBadHex     = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	escapeReplacer = strings.NewReplacer(
		`\r`, "\r",
		`\n`, "\n",
		`\t`, "\t",
		`\0`, "\x00",
		`\\`, `\`,
	)
)

// Banner converts literal escape sequences that survived in a banner string
// (for example the two characters backslash + "x00") into real bytes.
func Banner(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	if strings.Contains(s, `\x`) {
		s = hexEscape.ReplaceAllStringFunc(s, func(m string) string {
			v, err := strconv.ParseUint(m[2:], 16, 8)
			if err != nil {
				return m
			}
			return string(rune(v))
		})
	}
	return escapeReplacer.Replace(s)
}

// SanitizeJSON rewrites the non-standard "\xHH" escape into the "\u00HH" form
// that encoding/json accepts. It allows the client to consume scanner dumps
// that are "almost JSON" without preprocessing by hand.
func SanitizeJSON(raw []byte) []byte {
	if !bytes.Contains(raw, []byte(`\x`)) {
		return raw
	}
	return jsonBadHex.ReplaceAll(raw, []byte(`\u00$1`))
}
