//go:build authpg

package auth

import _ "github.com/jackc/pgx/v5/stdlib" // registers "pgx" for the PostgreSQL review run

func init() { pgDriverLinked = true }
