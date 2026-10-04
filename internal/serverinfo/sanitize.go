package serverinfo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var privateText = regexp.MustCompile(`(?i)(https?://|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|[0-9]{1,3}(\.[0-9]{1,3}){3}|password|passwd|bearer|authorization|api[_-]?key|token\s*[:=]|secret\s*[:=]|-----BEGIN|[\\/])`)
var serviceName = regexp.MustCompile(`^[a-zA-Z0-9_.@$ -]{1,120}$`)
var userInstance = regexp.MustCompile(`_[a-fA-F0-9]{4,}$`)

func publicText(s string, max int) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > max || !utf8.ValidString(s) || privateText.MatchString(s) {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return s
}
func filterServices(items []Service, key []byte) []Service {
	result := []Service{}
	if len(key) != 32 {
		return result
	}
	for _, v := range items {
		original := v.Name
		if !serviceName.MatchString(original) {
			continue
		}
		// Per-user instances may encode usernames or logon identifiers. Keep the
		// service family label, without publishing the identity-bearing suffix.
		if i := strings.IndexByte(v.Name, '@'); i >= 0 {
			v.Name = v.Name[:i] + "_instance.service"
			// Instance descriptions may include a username as well. Use the
			// normalized family instead of exporting an arbitrary description.
			v.DisplayName = v.Name
		}
		v.Name = userInstance.ReplaceAllString(v.Name, "_instance")
		if publicText(v.Name, 120) == "" {
			continue
		}
		// A keyed identifier preserves distinct instances without publishing a
		// user/logon suffix or an enumerable unkeyed hash. It lasts this process.
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(original))
		v.ID = hex.EncodeToString(mac.Sum(nil)[:16])
		v.DisplayName = publicText(v.DisplayName, 160)
		if v.DisplayName == "" {
			v.DisplayName = v.Name
		}
		v.DisplayName = userInstance.ReplaceAllString(v.DisplayName, "_instance")
		switch v.Status {
		case "running", "stopped", "paused", "pending", "unknown":
		default:
			v.Status = "unknown"
		}
		switch v.StartType {
		case "automatic", "manual", "disabled", "unknown":
		default:
			v.StartType = "unknown"
		}
		result = append(result, v)
		if len(result) >= ServiceLimit {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result
}
