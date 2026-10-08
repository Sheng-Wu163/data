// Package model defines the wire types exchanged between the client and the
// fingerprint server, plus a tolerant parser for raw scanner payloads.
package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Input is a single raw network observation: an address, a port and the raw
// banner bytes captured from the service (already decoded to a string).
type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result is the fingerprint verdict for one Input. Protocol is always
// populated; it is set to "unknown" when no rule matches. Confidence is in
// the range [0,1].
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// ParseInputs accepts the several shapes an evaluator/client might send:
//
//   - a bare JSON array:            [ {"ip":...}, ... ]
//   - an envelope object:           {"items":[ ... ]} (also data/banners/records)
//   - a single record:              {"ip":...,"port":...,"banner":...}
//
// Keeping this tolerant means the service never fails merely because of an
// unexpected but reasonable wrapper.
func ParseInputs(raw []byte) ([]Input, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty payload")
	}

	switch trimmed[0] {
	case '[':
		var items []Input
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
		return items, nil
	case '{':
		var env struct {
			Items   []Input `json:"items"`
			Data    []Input `json:"data"`
			Banners []Input `json:"banners"`
			Records []Input `json:"records"`
		}
		if err := json.Unmarshal(trimmed, &env); err == nil {
			for _, candidate := range [][]Input{env.Items, env.Data, env.Banners, env.Records} {
				if candidate != nil {
					return candidate, nil
				}
			}
		}
		var single Input
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return nil, fmt.Errorf("invalid JSON object: %w", err)
		}
		return []Input{single}, nil
	default:
		return nil, errors.New("payload must be a JSON array or object")
	}
}
