package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPrintClaimValue(t *testing.T) {
	tests := []struct {
		name       string
		givenLabel string
		givenKey   string
		givenValue any
	}{
		{
			name:       "string value",
			givenLabel: "label",
			givenKey:   "string_key",
			givenValue: "string",
		},
		{
			name:       "int value",
			givenLabel: "label",
			givenKey:   "int_key",
			givenValue: 123.0,
		},
		{
			name:       "float value",
			givenLabel: "label",
			givenKey:   "float_key",
			givenValue: 123.45,
		},
		{
			name:       "bool value",
			givenLabel: "label",
			givenKey:   "bool_key",
			givenValue: true,
		},
		{
			name:       "list value",
			givenLabel: "label",
			givenKey:   "list_key",
			givenValue: []any{"list", "of", "values"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = w

			printClaimValue(tt.givenLabel, tt.givenKey, tt.givenValue)

			w.Close()
			os.Stdout = old

			var buf bytes.Buffer
			io.Copy(&buf, r)

			output := buf.String()

			if !strings.Contains(output, tt.givenLabel) {
				t.Errorf("expected label '%s' not found in output for test '%s'", tt.givenLabel, tt.name)
			}

			switch v := tt.givenValue.(type) {
			case string:
				if !strings.Contains(output, v) {
					t.Errorf("expected string value '%s' not found in output for test '%s'", v, tt.name)
				}
			case float64:
				if v == float64(int64(v)) {
					if !strings.Contains(output, strings.TrimRight(fmt.Sprintf("%.0f", v), ".0")) {
						t.Errorf("expected int value '%v' not found in output for test '%s'", v, tt.name)
					}
				} else {
					if !strings.Contains(output, fmt.Sprintf("%g", v)) {
						t.Errorf("expected float value '%g' not found in output for test '%s'", v, tt.name)
					}
				}
			case bool:
				if !strings.Contains(output, fmt.Sprintf("%t", v)) {
					t.Errorf("expected bool value '%t' not found in output for test '%s'", v, tt.name)
				}
			case []any:
				for _, item := range v {
					if !strings.Contains(output, fmt.Sprintf("%v", item)) {
						t.Errorf("expected list item '%v' not found in output for test '%s'", item, tt.name)
					}
				}
			}
		})
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		input    time.Time
		expected string
	}{
		{
			name:     "about an hour ago",
			input:    now.Add(-1 * time.Hour),
			expected: "1 hour ago",
		},
		{
			name:     "2 hours ago",
			input:    now.Add(-2 * time.Hour),
			expected: "2 hours ago",
		},
		{
			name:     "a minute ago",
			input:    now.Add(-1 * time.Minute),
			expected: "1 minute ago",
		},
		{
			name:     "in 5 minutes",
			input:    now.Add(5 * time.Minute),
			expected: "in 5 minutes",
		},
		{
			name:     "just now",
			input:    now.Add(-5 * time.Second),
			expected: "just now",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := relativeTime(tt.input, now)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestPluralize(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		singular string
		expected string
	}{
		{
			name:     "zero items",
			count:    0,
			singular: "item",
			expected: "0 items",
		},
		{
			name:     "one item",
			count:    1,
			singular: "item",
			expected: "1 item",
		},
		{
			name:     "multiple items",
			count:    5,
			singular: "item",
			expected: "5 items",
		},
		{
			name:     "one person",
			count:    1,
			singular: "person",
			expected: "1 person",
		},
		{
			name:     "multiple persons",
			count:    3,
			singular: "person",
			expected: "3 persons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pluralize(tt.count, tt.singular)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
