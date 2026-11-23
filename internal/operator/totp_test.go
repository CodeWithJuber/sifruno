package operator

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA-1 rows. The RFC prints 8 digits; a 6-digit code
// is the same truncated value modulo 10^6, i.e. its last 6 digits.
func TestHOTPMatchesRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := hotp(key, uint64(v.unix/totpPeriod)); got != v.want {
			t.Fatalf("time %d: got %s want %s", v.unix, got, v.want)
		}
	}
}

func TestVerifyTOTPWindowReplayAndFormat(t *testing.T) {
	secret := totpEncoding.EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1234567890, 0)
	step := now.Unix() / totpPeriod
	code := func(s int64) string { return hotp([]byte("12345678901234567890"), uint64(s)) }
	for _, d := range []int64{-1, 0, 1} {
		got, ok := verifyTOTP(secret, code(step+d), now, -1)
		if !ok || got != step+d {
			t.Fatalf("offset %d refused", d)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := verifyTOTP(secret, code(step+d), now, -1); ok {
			t.Fatalf("offset %d accepted outside the window", d)
		}
	}
	if _, ok := verifyTOTP(secret, code(step), now, step); ok {
		t.Fatal("a used code was accepted again")
	}
	if _, ok := verifyTOTP(secret, code(step-1), now, step); ok {
		t.Fatal("an older code was accepted after a newer one")
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", " 12345", "１２３４５６"} {
		if _, ok := verifyTOTP(secret, bad, now, -1); ok {
			t.Fatalf("malformed code %q accepted", bad)
		}
	}
	if _, ok := verifyTOTP(secret[:31], code(step), now, -1); ok {
		t.Fatal("short secret accepted")
	}
}

func TestTOTPSecretAndURI(t *testing.T) {
	a, err := newTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newTOTPSecret()
	if a == b || len(a) != 32 {
		t.Fatal("secrets must be random 32-character values")
	}
	if _, ok := decodeTOTPSecret(a); !ok {
		t.Fatal("generated secret does not decode")
	}
	uri := totpURI("admin", a)
	for _, part := range []string{"otpauth://totp/Sifruno:admin?", "secret=" + a, "issuer=Sifruno", "digits=6", "period=30", "algorithm=SHA1"} {
		if !strings.Contains(uri, part) {
			t.Fatalf("URI missing %q", part)
		}
	}
}
