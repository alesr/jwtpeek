package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/alesr/jwtpeek"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func main() {
	var (
		tokenStr string
		secret   string
	)

	flag.StringVar(&tokenStr, "token", "", "JWT token to decode")
	flag.StringVar(&secret, "secret", "", "HMAC secret for signature verification (optional)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sUsage:%s jwtpeek -token <jwt> [-secret <key>]\n\n", colorBold, colorReset)
		fmt.Fprintf(os.Stderr, "Decode and inspect a JSON Web Token.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  jwtpeek -token eyJhbGciOiJIUzI1NiIs...\n")
		fmt.Fprintf(os.Stderr, "  jwtpeek -token eyJhbGciOiJIUzI1NiIs... -secret mysecret\n")
	}
	flag.Parse()

	if tokenStr == "" {
		if args := flag.Args(); len(args) > 0 {
			tokenStr = strings.TrimSpace(args[0])
		}
	}

	if tokenStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := run(tokenStr, secret); err != nil {
		fmt.Fprintf(os.Stderr, "%s✗ Error:%s %v\n", colorRed, colorReset, err)
		os.Exit(1)
	}
}

func run(tokenStr, secret string) error {
	token, err := jwtpeek.Decode(tokenStr)
	if err != nil {
		return err
	}

	printHeader(token)
	fmt.Println()
	printPayload(token)
	fmt.Println()
	printStatus(token, secret)

	return nil
}

func printHeader(token *jwtpeek.Token) {
	printSection("HEADER")

	printed := make(map[string]bool)
	priorityKeys := []string{"alg", "typ", "kid", "jku", "x5u", "x5c", "cty"}
	for _, k := range priorityKeys {
		if v, exists := token.Header.Raw[k]; exists {
			printField(jwtpeek.HeaderLabel(k), fmt.Sprintf("%v", v))
			printed[k] = true
		}
	}

	var remaining []string
	for k := range token.Header.Raw {
		if !printed[k] {
			remaining = append(remaining, k)
		}
	}
	sort.Strings(remaining)
	for _, k := range remaining {
		printField(jwtpeek.HeaderLabel(k), fmt.Sprintf("%v", token.Header.Raw[k]))
	}
}

func printPayload(token *jwtpeek.Token) {
	printSection("PAYLOAD")

	if len(token.Claims) == 0 {
		fmt.Printf("  %s(no claims)%s\n", colorGray, colorReset)
		return
	}

	stdKeys := jwtpeek.StandardClaimKeys()
	standardOrder := []string{"iss", "sub", "aud", "jti", "iat", "nbf", "exp"}
	printed := make(map[string]bool)

	for _, key := range standardOrder {
		val, exists := token.Claims[key]
		if !exists {
			continue
		}
		printed[key] = true
		label := stdKeys[key]
		printClaimValue(label, key, val)
	}

	extra := token.ExtraClaimKeys()
	if len(extra) > 0 && len(printed) > 0 {
		fmt.Printf("  %s────────────────────────────────────%s\n", colorGray, colorReset)
	}
	for _, key := range extra {
		printClaimValue(key, key, token.Claims[key])
	}
}

func printStatus(token *jwtpeek.Token, secret string) {
	printSection("STATUS")

	now := time.Now()
	printCheck(true, "Structure", "Valid JWT with 3 parts")
	printCheck(true, "Algorithm", token.Header.Algorithm)

	if iat := token.IssuedAt(); iat != nil {
		elapsed := relativeTime(*iat, now)
		printCheck(true, "Issued At", fmt.Sprintf("Issued %s", elapsed))
	}
	if exp := token.ExpiresAt(); exp != nil {
		if token.IsExpired() {
			elapsed := relativeTime(*exp, now)
			printCheck(false, "Expired", fmt.Sprintf("Token expired %s", elapsed))
		} else {
			remaining := relativeTime(*exp, now)
			printCheck(true, "Expires", fmt.Sprintf("Token expires %s", remaining))
		}
	} else {
		printWarn("Expiration", "No 'exp' claim present")
	}

	// not before
	if nbf := token.NotBefore(); nbf != nil {
		if token.IsNotYetValid() {
			until := relativeTime(*nbf, now)
			printCheck(false, "Not Before", fmt.Sprintf("Token not yet valid, usable %s", until))
		} else {
			printCheck(true, "Not Before", "Token is active")
		}
	}

	// sig
	if secret != "" {
		valid, err := token.VerifyHMAC(secret)
		if err != nil {
			printWarn("Signature", fmt.Sprintf("Cannot verify: %v", err))
		} else if valid {
			printCheck(true, "Signature", "Valid (verified with provided secret)")
		} else {
			printCheck(false, "Signature", "Invalid (does not match provided secret)")
		}
	} else {
		printWarn("Signature", "Not verified (use -secret to verify)")
	}
}

func printSection(title string) {
	fmt.Printf("%s%s── %s ──────────────────────────────────%s\n", colorBold, colorCyan, title, colorReset)
}

func printField(label, value string) { fmt.Printf("  %-16s %s\n", label, value) }

func printClaimValue(label, key string, val any) {
	if jwtpeek.IsTimeClaim(key) {
		if ts, ok := toFloat64(val); ok {
			t := time.Unix(int64(ts), 0).UTC()
			rel := relativeTime(t, time.Now())
			fmt.Printf("  %-16s %s%s%s %s(%s)%s\n",
				label,
				colorBold, t.Format(time.RFC3339), colorReset,
				colorDim, rel, colorReset,
			)
			return
		}
	}

	switch v := val.(type) {
	case string:
		fmt.Printf("  %-16s %s\n", label, v)
	case float64:
		if v == math.Trunc(v) {
			fmt.Printf("  %-16s %.0f\n", label, v)
		} else {
			fmt.Printf("  %-16s %g\n", label, v)
		}
	case bool:
		fmt.Printf("  %-16s %t\n", label, v)
	case nil:
		fmt.Printf("  %-16s %snull%s\n", label, colorGray, colorReset)
	default:
		data, err := json.MarshalIndent(v, "                   ", "  ")
		if err != nil {
			fmt.Printf("  %-16s %v\n", label, v)
			return
		}
		fmt.Printf("  %-16s %s\n", label, string(data))
	}
}

func printCheck(ok bool, label, msg string) {
	if ok {
		fmt.Printf("  %s✓%s %-14s %s\n", colorGreen, colorReset, label, msg)
	} else {
		fmt.Printf("  %s✗%s %-14s %s%s%s\n", colorRed, colorReset, label, colorRed, msg, colorReset)
	}
}

func printWarn(label, msg string) {
	fmt.Printf("  %s⚠%s %-14s %s%s%s\n", colorYellow, colorReset, label, colorYellow, msg, colorReset)
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func relativeTime(t, now time.Time) string {
	d := now.Sub(t)
	future := d < 0
	if future {
		d = -d
	}

	var result string
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		mins := int(d.Minutes())
		result = pluralize(mins, "minute")
	case d < 24*time.Hour:
		hours := int(d.Hours())
		result = pluralize(hours, "hour")
	case d < 30*24*time.Hour:
		days := int(d.Hours() / 24)
		result = pluralize(days, "day")
	case d < 365*24*time.Hour:
		months := int(d.Hours() / 24 / 30)
		result = pluralize(months, "month")
	default:
		years := int(d.Hours() / 24 / 365)
		result = pluralize(years, "year")
	}

	if future {
		return "in " + result
	}
	return result + " ago"
}

func pluralize(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
