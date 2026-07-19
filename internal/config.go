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
	AddrHTTP             string `toml:"addr_http"`
	AddrGRPC             string `toml:"addr_grpc"`
	AddrEmailService     string `toml:"add_email_service"`
	URLFrontend          string `toml:"url_frontend"`
	ResetPasswordMessage string `toml:"reset_password_message"`
}
type JWTConfig struct {
	Secret          string `toml:"secret"`
	AccessTokenTTL  string `toml:"access_token_ttl"`
	RefreshTokenTTL string `toml:"refresh_token_ttl"`
}
