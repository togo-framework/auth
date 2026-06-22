// Package auth is togo's base authentication system: JWT token auth, bcrypt
// passwords, a self-contained users store (via the ORM), multi-guard, and
// roles/permissions (RBAC). It's the default auth driver; Supabase/Firebase/
// OAuth/WorkOS ship as driver plugins that depend on this package.
//
// Install: `togo install togo-framework/auth` (blank-import registers it).
package auth

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/togo-framework/togo"
	"github.com/togo-framework/togo/orm"
)

func init() {
	togo.RegisterProviderFunc("auth", togo.PriorityLate+5, func(k *togo.Kernel) error {
		svc, err := New(k)
		if err != nil {
			return err
		}
		k.Set("auth", svc)
		svc.mountRoutes()
		return nil
	})
}

// User is the stored account. All columns are TEXT for cross-driver portability.
type User struct {
	ID           string `db:"id" json:"id"`
	Email        string `db:"email" json:"email"`
	PasswordHash string `db:"password_hash" json:"-"`
	Roles        string `db:"roles" json:"roles"`
	Permissions  string `db:"permissions" json:"permissions"`
	CreatedAt    string `db:"created_at" json:"created_at"`
}

// Identity is the authenticated principal exposed to the app.
type Identity struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Guard       string   `json:"guard"`
}

// Can reports whether the identity has a permission.
func (i Identity) Can(perm string) bool { return contains(i.Permissions, perm) }

// HasRole reports whether the identity has a role.
func (i Identity) HasRole(role string) bool { return contains(i.Roles, role) }

// Authenticator verifies credentials and loads identities. Drivers (supabase,
// oauth, …) implement this; the default is DB + bcrypt.
type Authenticator interface {
	Attempt(ctx context.Context, email, password string) (*Identity, error)
	ByID(ctx context.Context, id string) (*Identity, error)
}

// Guard pairs a name with an Authenticator — enabling multi-guard setups.
type Guard struct {
	Name string
	Auth Authenticator
}

// Service is the auth runtime stored on the kernel (k.Get("auth")).
type Service struct {
	k        *togo.Kernel
	secret   []byte
	ttl      time.Duration
	guards   map[string]*Guard
	def      string
}

// New builds the service, ensures the users table exists, and registers the
// default DB-backed guard.
func New(k *togo.Kernel) (*Service, error) {
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = os.Getenv("JWT_SECRET")
	}
	if secret == "" {
		secret = "dev-insecure-secret-change-me"
		k.Log.Warn("AUTH_SECRET not set — using an insecure dev secret")
	}
	s := &Service{
		k:      k,
		secret: []byte(secret),
		ttl:    24 * time.Hour,
		guards: map[string]*Guard{},
		def:    "api",
	}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	s.RegisterGuard("api", &dbAuthenticator{s: s})
	return s, nil
}

// RegisterGuard adds a named guard (multi-guard support).
func (s *Service) RegisterGuard(name string, a Authenticator) {
	s.guards[name] = &Guard{Name: name, Auth: a}
}

// Guard returns a named guard (or the default).
func (s *Service) Guard(name string) *Guard {
	if name == "" {
		name = s.def
	}
	return s.guards[name]
}

// FromKernel fetches the auth service from the kernel container.
func FromKernel(k *togo.Kernel) (*Service, bool) {
	v, ok := k.Get("auth")
	if !ok {
		return nil, false
	}
	svc, ok := v.(*Service)
	return svc, ok
}

func (s *Service) users() *orm.Query[User] {
	return orm.For[User](s.sqlDB(), s.k.Dialect(), "users")
}

func (s *Service) ensureSchema(ctx context.Context) error {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS users (
		id text PRIMARY KEY,
		email text UNIQUE NOT NULL,
		password_hash text NOT NULL,
		roles text NOT NULL DEFAULT '',
		permissions text NOT NULL DEFAULT '',
		created_at text NOT NULL
	)`)
	return err
}

// IssueToken signs a JWT for an identity.
func (s *Service) IssueToken(id Identity) (string, error) {
	claims := jwt.MapClaims{
		"sub":   id.ID,
		"email": id.Email,
		"roles": strings.Join(id.Roles, ","),
		"perms": strings.Join(id.Permissions, ","),
		"guard": id.Guard,
		"exp":   time.Now().Add(s.ttl).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

// Verify parses a token into an Identity.
func (s *Service) Verify(token string) (*Identity, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return s.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	return &Identity{
		ID:          str(claims["sub"]),
		Email:       str(claims["email"]),
		Roles:       splitCSV(str(claims["roles"])),
		Permissions: splitCSV(str(claims["perms"])),
		Guard:       str(claims["guard"]),
	}, nil
}

// hash + compare helpers.
func hashPassword(p string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(b), err
}
func checkPassword(hash, p string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
