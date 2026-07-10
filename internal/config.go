package internal

type Config struct {
	Database DatabaseConfig `toml:"database"`
	JWT      JWTConfig      `toml:"jwt"`
	LogLevel string         `toml:"loglevel"`
	Service  Service        `toml:"service"`
}

type DatabaseConfig struct {
	Addr string `toml:"addr"`
}

type Service struct {
	Addr string `toml:"addr"`
}
type JWTConfig struct {
	Secret          string `toml:"secret"`
	AccessTokenTTL  string `toml:"access_token_ttl"`
	RefreshTokenTTL string `toml:"refresh_token_ttl"`
}
