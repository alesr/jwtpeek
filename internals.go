package jwtp

import (
	"encoding/json"
	"time"
)

func stringFromHeader(h map[string]any, key string) string {
	if v, ok := h[key].(string); ok {
		return v
	}
	return ""
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func timeClaim(claims map[string]any, key string) *time.Time {
	val, exists := claims[key]
	if !exists {
		return nil
	}

	var ts float64
	switch v := val.(type) {
	case float64:
		ts = v
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return nil
		}
		ts = f
	default:
		return nil
	}
	t := time.Unix(int64(ts), 0).UTC()
	return &t
}
