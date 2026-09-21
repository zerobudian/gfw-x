package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashing follows the PHC string format used by argon2.
//   - New hashes:  $argon2id$v=19$m=65536,t=2,p=1$<saltB64>$<keyB64>
//   - Legacy hashes (pre-1.1): plain hex of the double salted SHA-256. These
//     are still accepted for migration and are transparently upgraded to
//     Argon2id on the next successful login.

const (
	argon2Time    = 2
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 1
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// hasPassword stores a plaintext password using Argon2id with a fresh random
// salt. The result is a self-describing PHC string so verification can parse
// the parameters from the stored value (allowing future parameter changes).
func hashPassword(pw string) string {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		// Extremely unlikely; fall back to a deterministic salt derived from
		// the password so we never store a hash built on zero salt.
		h := sha256.Sum256([]byte(pw))
		copy(salt, h[:argon2SaltLen])
	}
	key := argon2.IDKey([]byte(pw), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// verifyAndUpgrade checks password pw against the stored hash. When stored is a
// legacy SHA-256 hash and pw matches, it returns an upgraded Argon2id hash so
// the storage layer can persist the migration. Ok=false means wrong password.
func verifyAndUpgrade(pw, stored string) (upgraded string, ok bool) {
	upgraded, ok = "", false
	if strings.HasPrefix(stored, "$argon2id$") {
		return "", verifyArgon2(pw, stored)
	}
	// Legacy double salted SHA-256.
	if subtle.ConstantTimeCompare([]byte(legacyHash(pw)), []byte(stored)) == 1 {
		return hashPassword(pw), true
	}
	return "", false
}

func verifyArgon2(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	// $argon2id$v=19$m=...,t=...,p=...$salt$key  → 6 parts, parts[0] is "".
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}
	if version != argon2.Version {
		return false
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	expected := argon2.IDKey([]byte(pw), salt, iterations, memory, parallelism, uint32(len(key)))
	return subtle.ConstantTimeCompare(expected, key) == 1
}

// legacyHash reproduces the pre-1.1 fixed-salt double SHA-256 so existing
// configs keep working and can be migrated.
func legacyHash(pw string) string {
	salt := "gfw-x-static-salt"
	inner := sha256.Sum256([]byte(salt + pw))
	outer := sha256.Sum256([]byte(string(inner[:]) + salt))
	return hex.EncodeToString(outer[:])
}

// isArgon2Hash reports whether a stored hash is in the modern PHC format.
func isArgon2Hash(stored string) bool { return strings.HasPrefix(stored, "$argon2id$") }
