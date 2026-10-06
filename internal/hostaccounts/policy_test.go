package hostaccounts

import (
	"strings"
	"testing"
)

const localNSSFixture = "passwd: files\ngroup: files\nshadow: files\n"
const mailNoFixture = "CREATE_MAIL_SPOOL=no\n"

func TestFilesOnlyNSSPolicy(t *testing.T) {
	for name, input := range map[string]string{
		"literal":             localNSSFixture,
		"comments_whitespace": "# synthetic policy\nshadow:\tfiles # local\ngroup: files\n passwd : files\nhosts: dns files\n",
		"no_final_newline":    strings.TrimSuffix(localNSSFixture, "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if e := filesOnlyNSS([]byte(input)); e != nil {
				t.Fatal("supported policy refused", e)
			}
		})
	}
	for name, input := range map[string]string{
		"empty":            "",
		"missing_passwd":   "group: files\nshadow: files\n",
		"missing_group":    "passwd: files\nshadow: files\n",
		"missing_shadow":   "passwd: files\ngroup: files\n",
		"duplicate_passwd": localNSSFixture + "passwd: files\n",
		"duplicate_group":  localNSSFixture + "group: files\n",
		"duplicate_shadow": localNSSFixture + "shadow: files\n",
		"sss":              strings.Replace(localNSSFixture, "passwd: files", "passwd: files sss", 1),
		"compat":           strings.Replace(localNSSFixture, "group: files", "group: compat", 1),
		"systemd":          strings.Replace(localNSSFixture, "shadow: files", "shadow: files systemd", 1),
		"action":           strings.Replace(localNSSFixture, "passwd: files", "passwd: files [SUCCESS=return]", 1),
		"uppercase":        strings.Replace(localNSSFixture, "files", "FILES", 1),
		"nul_provider":     localNSSFixture + "passwd: files\x00sss\n",
		"nul_comment":      localNSSFixture + "# ignored\x00passwd: sss\n",
		"nul_unrelated":    localNSSFixture + "hosts: files\x00dns\n",
	} {
		t.Run(name, func(t *testing.T) {
			if e := filesOnlyNSS([]byte(input)); e != ErrUnavailable {
				t.Fatal("unsupported policy accepted", e)
			}
		})
	}
	bounded := localNSSFixture + "#" + strings.Repeat(" ", maxNSSPolicyBytes-len(localNSSFixture)-1)
	if filesOnlyNSS([]byte(bounded)) != nil || filesOnlyNSS([]byte(bounded+" ")) != ErrUnavailable {
		t.Fatal("NSS byte bound not enforced")
	}
}

func TestServiceAccountDefaultsPolicy(t *testing.T) {
	for name, input := range map[string]string{
		"literal_no":           mailNoFixture,
		"literal_yes":          "CREATE_MAIL_SPOOL=yes\n",
		"yes_no_final_newline": "CREATE_MAIL_SPOOL=yes",
		"unrelated":            "# Synthetic fixture\nGROUP=100\n" + mailNoFixture,
		"no_final_newline":     strings.TrimSuffix(mailNoFixture, "\n"),
		"legacy_1022":          mailNoFixture + "#" + strings.Repeat(" ", 1021),
	} {
		t.Run(name, func(t *testing.T) {
			if e := serviceAccountDefaults([]byte(input)); e != nil {
				t.Fatal("supported defaults refused", e)
			}
		})
	}
	for name, input := range map[string]string{
		"missing": "GROUP=100\n", "unknown": "CREATE_MAIL_SPOOL=maybe\n",
		"mixed_duplicate":       mailNoFixture + "CREATE_MAIL_SPOOL=yes\n",
		"yes_whitespace":        "CREATE_MAIL_SPOOL=yes \n",
		"yes_quoted":            "CREATE_MAIL_SPOOL=\"yes\"\n",
		"yes_nul":               "CREATE_MAIL_SPOOL=yes\n#\x00",
		"duplicate":             mailNoFixture + mailNoFixture,
		"quoted":                "CREATE_MAIL_SPOOL=\"no\"\n",
		"leading_key_space":     " CREATE_MAIL_SPOOL=no\n",
		"trailing_key_space":    "CREATE_MAIL_SPOOL =no\n",
		"value_space":           "CREATE_MAIL_SPOOL= no\n",
		"trailing_space":        "CREATE_MAIL_SPOOL=no \n",
		"crlf":                  "CREATE_MAIL_SPOOL=no\r\n",
		"commented":             "#CREATE_MAIL_SPOOL=no\n",
		"inline_comment":        "CREATE_MAIL_SPOOL=no # disabled\n",
		"nul":                   mailNoFixture + "#\x00CREATE_MAIL_SPOOL=yes\n",
		"legacy_1023":           mailNoFixture + "#" + strings.Repeat(" ", 1022),
		"legacy_chunk_override": mailNoFixture + "#" + strings.Repeat(" ", 1022) + "CREATE_MAIL_SPOOL=yes\n",
		"unrelated_overlong":    mailNoFixture + strings.Repeat("a", 1023),
	} {
		t.Run(name, func(t *testing.T) {
			if e := serviceAccountDefaults([]byte(input)); e != ErrUnavailable {
				t.Fatal("unsupported defaults accepted", e)
			}
		})
	}
	for _, literal := range []string{mailNoFixture, "CREATE_MAIL_SPOOL=yes\n"} {
		remaining := maxUseraddDefaultsBytes - len(literal)
		bounded := literal + strings.Repeat("#\n", remaining/2) + strings.Repeat("#", remaining%2)
		if len(bounded) != maxUseraddDefaultsBytes || serviceAccountDefaults([]byte(bounded)) != nil || serviceAccountDefaults([]byte(bounded+"#")) != ErrUnavailable {
			t.Fatal("mail defaults byte bound not enforced")
		}
		for _, length := range []int{1022, 1023} {
			input := literal + "#" + strings.Repeat(" ", length-1) + "\n"
			got := serviceAccountDefaults([]byte(input))
			if length == 1022 && got != nil || length == 1023 && got != ErrUnavailable {
				t.Fatalf("physical line length %d: %v", length, got)
			}
		}
	}
}
