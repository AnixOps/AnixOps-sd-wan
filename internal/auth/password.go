package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
)

const DefaultPasswordIterations = 100000

type PasswordUser struct {
	TenantID   string `json:"tenant_id"`
	SubjectID  string `json:"subject_id"`
	Roles      []Role `json:"roles"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}

type PasswordAuthenticator struct {
	users map[string]PasswordUser
}

func NewPasswordUser(tenantID, subjectID, password string, roles []Role, iterations int) (PasswordUser, error) {
	if tenantID == "" {
		return PasswordUser{}, fmt.Errorf("password user tenant id is required")
	}
	if subjectID == "" {
		return PasswordUser{}, fmt.Errorf("password user subject id is required")
	}
	if password == "" {
		return PasswordUser{}, fmt.Errorf("password is required")
	}
	if len(roles) == 0 {
		return PasswordUser{}, fmt.Errorf("password user roles are required")
	}
	if iterations <= 0 {
		iterations = DefaultPasswordIterations
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return PasswordUser{}, fmt.Errorf("generate password salt: %w", err)
	}
	hash := derivePasswordKey([]byte(password), salt, iterations, 32)
	return PasswordUser{
		TenantID:   tenantID,
		SubjectID:  subjectID,
		Roles:      append([]Role(nil), roles...),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Hash:       base64.StdEncoding.EncodeToString(hash),
		Iterations: iterations,
	}, nil
}

func LoadPasswordAuthenticator(path string) (*PasswordAuthenticator, error) {
	if path == "" {
		return nil, fmt.Errorf("password users file is required")
	}
	if err := validatePrivateAuthFile(path, "password users file"); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read password users file: %w", err)
	}
	var users []PasswordUser
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("decode password users file: %w", err)
	}
	return NewPasswordAuthenticator(users)
}

func NewPasswordAuthenticator(users []PasswordUser) (*PasswordAuthenticator, error) {
	byKey := make(map[string]PasswordUser, len(users))
	for _, user := range users {
		if err := user.Validate(); err != nil {
			return nil, err
		}
		key := passwordUserKey(user.TenantID, user.SubjectID)
		if _, exists := byKey[key]; exists {
			return nil, fmt.Errorf("duplicate password user %s/%s", user.TenantID, user.SubjectID)
		}
		user.Roles = append([]Role(nil), user.Roles...)
		byKey[key] = user
	}
	return &PasswordAuthenticator{users: byKey}, nil
}

func (a *PasswordAuthenticator) Authenticate(tenantID, subjectID, password string) (Subject, bool, error) {
	if a == nil {
		return Subject{}, false, fmt.Errorf("password authenticator is not configured")
	}
	user, ok := a.users[passwordUserKey(tenantID, subjectID)]
	if !ok {
		return Subject{}, false, nil
	}
	if ok, err := user.CheckPassword(password); err != nil || !ok {
		return Subject{}, ok, err
	}
	return Subject{
		ID:       user.SubjectID,
		TenantID: user.TenantID,
		Roles:    append([]Role(nil), user.Roles...),
	}, true, nil
}

func (u PasswordUser) Validate() error {
	if u.TenantID == "" {
		return fmt.Errorf("password user tenant id is required")
	}
	if u.SubjectID == "" {
		return fmt.Errorf("password user subject id is required")
	}
	if len(u.Roles) == 0 {
		return fmt.Errorf("password user roles are required")
	}
	if u.Iterations <= 0 {
		return fmt.Errorf("password hash iterations must be positive")
	}
	if _, err := base64.StdEncoding.DecodeString(u.Salt); err != nil {
		return fmt.Errorf("decode password salt: %w", err)
	}
	if hash, err := base64.StdEncoding.DecodeString(u.Hash); err != nil {
		return fmt.Errorf("decode password hash: %w", err)
	} else if len(hash) != 32 {
		return fmt.Errorf("password hash must be 32 bytes")
	}
	return nil
}

func (u PasswordUser) CheckPassword(password string) (bool, error) {
	if err := u.Validate(); err != nil {
		return false, err
	}
	salt, err := base64.StdEncoding.DecodeString(u.Salt)
	if err != nil {
		return false, fmt.Errorf("decode password salt: %w", err)
	}
	want, err := base64.StdEncoding.DecodeString(u.Hash)
	if err != nil {
		return false, fmt.Errorf("decode password hash: %w", err)
	}
	got := derivePasswordKey([]byte(password), salt, u.Iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func passwordUserKey(tenantID, subjectID string) string {
	return tenantID + "\x00" + subjectID
}

func derivePasswordKey(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	for block := 1; block <= blocks; block++ {
		u := pbkdf2Block(password, salt, iterations, block)
		out = append(out, u...)
	}
	return out[:keyLen]
}

func pbkdf2Block(password, salt []byte, iterations, block int) []byte {
	mac := hmac.New(sha256.New, password)
	_, _ = mac.Write(salt)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], uint32(block))
	_, _ = mac.Write(counter[:])
	u := mac.Sum(nil)
	result := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		mac = hmac.New(sha256.New, password)
		_, _ = mac.Write(u)
		u = mac.Sum(nil)
		for j := range result {
			result[j] ^= u[j]
		}
	}
	return result
}
