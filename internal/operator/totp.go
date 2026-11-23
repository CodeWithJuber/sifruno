package operator

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// Time-based one-time codes (RFC 6238) with the parameters every common
// authenticator app accepts: HMAC-SHA1, 6 digits, 30-second steps. SHA-1 is
// what RFC 6238 apps implement; as an HMAC key it is not the weak point.
const (
	totpPeriod     = 30
	totpDigits     = 6
	totpSecretSize = 20 // bytes, the 160 bits RFC 4226 recommends
	totpSkew       = 1  // steps accepted on either side of now, for clock drift
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() (string, error) {
	b := make([]byte, totpSecretSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(b), nil
}

// decodeTOTPSecret accepts exactly the 32-character form newTOTPSecret makes:
// 160 bits fill 32 base32 characters with no leftover bits to vary.
func decodeTOTPSecret(s string) ([]byte, bool) {
	if len(s) != 32 {
		return nil, false
	}
	b, err := totpEncoding.DecodeString(s)
	return b, err == nil && len(b) == totpSecretSize
}

func validTOTPCode(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// hotp is RFC 4226 section 5.3: dynamic truncation of HMAC-SHA1(key, counter).
func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, value%1000000)
}

// verifyTOTP returns the time step the code belongs to. Steps at or before
// lastStep are refused, so a code cannot be used twice, even inside its
// 90-second acceptance window.
func verifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	key, ok := decodeTOTPSecret(secret)
	if !ok || !validTOTPCode(code) {
		return 0, false
	}
	current := now.Unix() / totpPeriod
	matched := int64(-1)
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		if step < 0 || step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(step))), []byte(code)) == 1 && matched < 0 {
			matched = step
		}
	}
	return matched, matched >= 0
}

// totpURI is the otpauth:// link authenticator apps open or import.
func totpURI(username, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", "Sifruno")
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + url.PathEscape("Sifruno:"+username) + "?" + q.Encode()
}
