/*
 * Copyright (C) 2024. Genome Research Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package server

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "crypto/tls" // Leave this to ensure that the TLS package is linked

	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	iconfig "github.com/cyverse/go-irodsclient/config"
	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/microcosm-cc/bluemonday"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

type ContextKey string

// SqyrrlServer is an HTTP server which contains an embedded iRODS client.
type SqyrrlServer struct {
	http.Server
	sqyrrlConfig    *Config
	oauth2Config    *oauth2.Config
	oidcConfig      *oidc.Config
	oidcProvider    *oidc.Provider
	sessionManager  *scs.SessionManager
	handlers        map[string]http.Handler              // The HTTP handlers, to simplify testing
	context         context.Context                      // Context for clean shutdown
	cancel          context.CancelFunc                   // Cancel function for the server
	logger          zerolog.Logger                       // Base logger from which the server creates its own sub-loggers
	iRODSEnvManager *iconfig.ICommandsEnvironmentManager // iRODS environment manager for
	// the embedded client
	iRODSAccount *types.IRODSAccount // iRODS account for the embedded client
	iRODSIndex   *ItemIndex          // ItemIndex of items in the iRODS server
}

type Config struct {
	Host             string
	Port             string
	IRODSEnvFilePath string // Path to the iRODS environment file
	IRODSPassword    string // Password for the iRODS account
	CertFilePath     string
	KeyFilePath      string
	ConfigFilePath   string // Path to a TOML configuration file
	EnableOIDC       bool
	OIDCClientID     string
	OIDCClientSecret string
	OIDCIssuerURL    string
	OIDCRedirectURL  string
	IRODSZoneForOIDC string // iRODS zone to use with OIDC id for authz
	IndexInterval    time.Duration
}

const AppName = "sqyrrl"

const (
	MinIndexInterval     = 10 * time.Second
	DefaultIndexInterval = 60 * time.Second
)

const (
	EnvClientID        = "OIDC_CLIENT_ID"
	EnvOIDCIssuerURL   = "OIDC_ISSUER_URL"
	EnvOIDCRedirectURL = "OIDC_CALLBACK_URL"
)

const (
	SessionKeyState       = "state"
	SessionKeyAccessToken = "access_token"
	SessionKeyUserEmail   = "user_email"
	SessionKeyUserName    = "user_name"
)

const correlationIDKey = ContextKey("correlation_id")
const staticContentDir = "static"

var userInputPolicy = bluemonday.StrictPolicy()

var (
	//go:embed templates/*
	templateFS embed.FS
	// HTML templates used by the server
	templates *template.Template

	//go:embed static/*
	staticContentFS embed.FS
)

// Embed the HTML templates at compile time
func init() {
	templates = template.Must(template.ParseFS(templateFS, "templates/*"))
}

// NewSqyrrlServer creates a new SqyrrlServer instance.
//
// This constructor sets up an iRODS account and configures routing for the server.
// The server is not started by this function. Call Start() on the returned server to
// start it. To stop the server, send SIGINT or SIGTERM to the process to trigger a
// graceful shutdown.
//
// The logger should be the root logger of the application. The server will create
// sub-loggers for its components.
//
// The config argument should be initialised by calling Configure before passing it to
// this function.
func NewSqyrrlServer(logger zerolog.Logger, config *Config,
	sessionManager *scs.SessionManager) (server *SqyrrlServer,
	err error) { // NRV
	if config.Host == "" {
		return nil, fmt.Errorf("server sqyrrlConfig %w: host", ErrMissingArgument)
	}
	if config.Port == "" {
		return nil, fmt.Errorf("server sqyrrlConfig %w: port", ErrMissingArgument)
	}
	if config.CertFilePath == "" {
		return nil,
			fmt.Errorf("server sqyrrlConfig %w: certificate file path", ErrMissingArgument)
	}

	if config.IndexInterval < MinIndexInterval {
		logger.Warn().
			Dur("interval", config.IndexInterval).
			Dur("min_interval", MinIndexInterval).
			Msg("Index interval too short, using the default interval")
		config.IndexInterval = DefaultIndexInterval
	}

	// The sub-logger adds "hostname and" "component" field to the log entries. Further
	// fields are added by other components e.g. in the HTTP handlers.
	var hostname string
	if hostname, err = os.Hostname(); err != nil {
		return nil, err
	}

	var cwd string
	cwd, err = os.Getwd()
	if err != nil {
		return nil, err
	}

	subLogger := logger.With().
		Str("hostname", hostname).
		Str("component", "server").Logger()

	var oidcConfig *oidc.Config
	var oidcProvider *oidc.Provider
	var oauth2Config *oauth2.Config

	if config.EnableOIDC {
		if config.OIDCClientID == "" {
			return nil, fmt.Errorf("server config %w: OIDC client ID",
				ErrMissingArgument)
		}
		if config.OIDCClientSecret == "" {
			return nil, fmt.Errorf("server config %w: OIDC client secret",
				ErrMissingArgument)
		}
		if config.OIDCIssuerURL == "" {
			return nil, fmt.Errorf("server config %w: OIDC issuer URL",
				ErrMissingArgument)
		}
		if config.OIDCRedirectURL == "" {
			return nil, fmt.Errorf("server config %w: OIDC redirect URL",
				ErrMissingArgument)
		}

		oidcConfig = &oidc.Config{
			ClientID: config.OIDCClientID,
		}

		oidcProvider, err = oidc.NewProvider(context.Background(), config.OIDCIssuerURL)
		if err != nil {
			return nil, err
		}

		var redirectURL *url.URL
		redirectURL, err = url.Parse(config.OIDCRedirectURL)
		if err != nil {
			return nil, err
		}

		oauth2Config = &oauth2.Config{
			ClientID:     config.OIDCClientID,
			ClientSecret: config.OIDCClientSecret,
			Endpoint:     oidcProvider.Endpoint(),
			RedirectURL:  redirectURL.JoinPath(EndpointAuthCallback).String(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}

		logger.Info().
			Str("auth_url", oidcProvider.Endpoint().AuthURL).
			Str("redirect_url", oauth2Config.RedirectURL).
			Msg("OIDC provider configured")
	}

	var iRODSEnvManager *iconfig.ICommandsEnvironmentManager
	if iRODSEnvManager, err = NewICommandsEnvironmentManager(subLogger, config.IRODSEnvFilePath); err != nil {
		logger.Err(err).Msg("Failed to create an iRODS environment manager")
		return nil, err
	}

	var iRODSAccount *types.IRODSAccount
	if iRODSAccount, err = NewIRODSAccount(subLogger, iRODSEnvManager, config.IRODSPassword); err != nil {
		logger.Err(err).Msg("Failed to get an iRODS account")
		return nil, err
	}

	if config.IRODSZoneForOIDC == "" {
		config.IRODSZoneForOIDC = iRODSAccount.ClientZone
		logger.Debug().Str("IRODSZoneForOIDC", config.IRODSZoneForOIDC).Msg("Setting IRODSZoneForOIDC to default of client zone")
	}

	addr := net.JoinHostPort(config.Host, config.Port)
	mux := http.NewServeMux()
	serverCtx, cancelServer := context.WithCancel(context.Background())

	server = &SqyrrlServer{
		http.Server{
			Addr: addr,
			// Wrap the handler to enable automatic session management by scs
			// Handler: sessionManager.LoadAndSave(mux),
			Handler: mux,
			BaseContext: func(listener net.Listener) context.Context {
				return serverCtx
			}},
		config,
		oauth2Config,
		oidcConfig,
		oidcProvider,
		sessionManager,
		make(map[string]http.Handler),
		serverCtx,
		cancelServer,
		subLogger,
		iRODSEnvManager,
		iRODSAccount,
		NewItemIndex([]Item{}),
	}

	err = server.setUpIndexing()
	if err != nil {
		return nil, err
	}

	server.setUpSignalHandler()
	server.addRoutes(mux)

	logger.Info().
		Str("host", config.Host).
		Str("port", config.Port).
		Str("cert_file", config.CertFilePath).
		Str("key_file", config.KeyFilePath).
		Str("irods_env", config.IRODSEnvFilePath).
		Bool("oidc_enabled", config.EnableOIDC).
		Str("cwd", cwd).
		Dur("index_interval", config.IndexInterval).Msg("Server configured")

	return server, nil
}

func (server *SqyrrlServer) IRODSEnvFilePath() string {
	return server.iRODSEnvManager.EnvironmentFilePath
}

func (server *SqyrrlServer) IRODSAuthFilePath() string {
	return server.iRODSEnvManager.PasswordFilePath
}

// GetHandler returns the handler for the named endpoint.
//
// This is used for ease of testing because it will return a handler configured with the
// server's session manager.
func (server *SqyrrlServer) GetHandler(endpoint string) (http.Handler, error) {
	// If the named handler is not in the handlers map, return an error
	if handler, ok := server.handlers[endpoint]; ok {
		return handler, nil
	}
	return nil, fmt.Errorf("no handler found for endpoint %s", endpoint)
}

// Start starts the server. This function blocks until the server is stopped.
//
// To stop the server, send SIGINT or SIGTERM to the process or call the server's Stop
// function directly from another goroutine. An error is returned if the server fails
// to start or if it fails to stop cleanly (with http.ErrServerClosed).
func (server *SqyrrlServer) Start() error {
	var serveErr, shutErr error

	config := server.sqyrrlConfig
	for _, path := range []string{config.CertFilePath, config.KeyFilePath,
		config.IRODSEnvFilePath} {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("server config %w: %s", err, path)
		}
	}

	go func() {
		logger := server.logger

		// The following make it easier to diagnose issues with missing files
		// given as relative paths. We don't abort on errors here because it's cleaner
		// to allow the server to try to start and clean up any resulting error in one
		// place.
		absCertFilePath, err := filepath.Abs(server.sqyrrlConfig.CertFilePath)
		if err != nil {
			logger.Err(err).
				Str("path", server.sqyrrlConfig.CertFilePath).
				Msg("Failed to get the absolute path of the certificate file")
		}
		absKeyFilePath, err := filepath.Abs(server.sqyrrlConfig.KeyFilePath)
		if err != nil {
			logger.Err(err).
				Str("path", server.sqyrrlConfig.KeyFilePath).
				Msg("Failed to get the absolute path of the key file")
		}

		err = server.ListenAndServeTLS(absCertFilePath, absKeyFilePath)

		logger.Info().Msg("Server stopped listening")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrServerClosed):
				logger.Info().Msg("Server closed cleanly")
			default:
				logger.Err(err).Msg("Server closed with an error")
				serveErr = err
				server.cancel() // If something went wrong, ensure that the server stops
			}
		}
	}()

	<-server.context.Done()

	shutErr = server.waitAndShutdown()

	return errors.Join(serveErr, shutErr)
}

// StartBackground starts the server in a goroutine. This function returns immediately.
// The error is returned only if the server fails to start, otherwise it is nil. The
// server can be stopped by calling the server's Stop function.
func (server *SqyrrlServer) StartBackground() (err error) { // NRV
	go func() {
		err = server.Start()
		if err != nil {
			server.logger.Err(err).Msg("Error starting server")
		}
	}()

	return err
}

// Stop stops the server. It provides a public means to call the server's cancel function.
func (server *SqyrrlServer) Stop() {
	server.cancel()
}

func (server *SqyrrlServer) setUpSignalHandler() {
	logger := server.logger

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-signals

		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			logger.Info().
				Str("signal", sig.String()).
				Msg("Server shutting down on signal")
			server.cancel()
		default:
			logger.Warn().
				Str("signal", sig.String()).
				Msg("Received signal")
		}
	}()
}

func (server *SqyrrlServer) setUpIndexing() (err error) { // NRV
	logger := server.logger

	var filesystem *fs.FileSystem
	filesystem, err = fs.NewFileSystemWithDefault(server.iRODSAccount, AppName)
	if err != nil {
		return err
	}

	// Query the iRODS server for items at regular intervals
	itemChan := queryAtIntervals(logger, server.context, server.sqyrrlConfig.IndexInterval,
		func() ([]Item, error) {
			return findItems(filesystem)
		})

	logger.Info().Dur("interval", server.sqyrrlConfig.IndexInterval).Msg("Indexing started")

	// Create an index of items. This goroutine updates the index from the item
	// channel. It is the only goroutine that receives from the channel and the only
	// one that updates the index, meaning it doesn't require a mutex for that.
	// However, the index may be read by multiple HTTP requests, so has a mutex to
	// prevent it being read during updates.
	go func() {
		for {
			select {
			case <-server.context.Done():
				logger.Info().Msg("Indexing cancelled")
				return
			case items := <-itemChan:
				server.iRODSIndex.SetItems(items)
				logger.Info().
					Str("index", server.iRODSIndex.String()).
					Msg("Updated index")
			}
		}
	}()

	return nil
}

func (server *SqyrrlServer) isAuthenticated(r *http.Request) bool {
	return server.getSessionAccessToken(r) != ""
}

func (server *SqyrrlServer) getSessionAccessToken(r *http.Request) string {
	return server.sessionManager.GetString(r.Context(), SessionKeyAccessToken)
}

func (server *SqyrrlServer) setSessionAccessToken(ctx context.Context, token string) {
	server.sessionManager.Put(ctx, SessionKeyAccessToken, token)
}

func (server *SqyrrlServer) getSessionUserEmail(r *http.Request) string {
	return server.sessionManager.GetString(r.Context(), SessionKeyUserEmail)
}

func (server *SqyrrlServer) setSessionUserEmail(ctx context.Context, email string) {
	server.sessionManager.Put(ctx, SessionKeyUserEmail, email)
}

func (server *SqyrrlServer) getSessionUserName(r *http.Request) string {
	return server.sessionManager.GetString(r.Context(), SessionKeyUserName)
}

func (server *SqyrrlServer) setSessionUserName(ctx context.Context, name string) {
	server.sessionManager.Put(ctx, SessionKeyUserName, name)
}

func (server *SqyrrlServer) waitAndShutdown() (err error) { // NRV
	logger := server.logger

	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTimeout()

	if err = server.Shutdown(timeoutCtx); err != nil {
		logger.Err(err).Msg("Error shutting down server")
	}
	logger.Info().Msg("Server shutdown cleanly")

	return err
}

// Configure sets up the server configuration. This function reads the configuration
// from the provided Config struct and updates it with values from the environment, if
// they are not already set. This is for backwards compatibility with previous versions
// of the server. It also validates and URLs provided in the configuration. If the
// configuration is invalid, it returns an error.
func Configure(logger zerolog.Logger, config *Config) error {
	// Fall back to environment variables if the configuration file does not specify them
	// and they are not overridden on the command line. This is for backwards compatibility
	var err error

	if config.EnableOIDC {
		if config.OIDCClientID == "" {
			var clientID string
			clientID, err = getEnv(EnvClientID)
			if err != nil {
				return err
			}
			logger.Info().Str("client_id",
				clientID).Msg("Configured OpenID Connect client ID from the environment")
			config.OIDCClientID = clientID
		}
		if config.OIDCIssuerURL == "" {
			var issuerURL string
			issuerURL, err = getEnv(EnvOIDCIssuerURL)
			if err != nil {
				return err
			}
			logger.Info().Str("issuer_url",
				issuerURL).Msg("Configured OpenID Connect issuer URL from the environment")
			config.OIDCIssuerURL = issuerURL
		}
		if config.OIDCRedirectURL == "" {
			var redirectURL string
			redirectURL, err = getEnv(EnvOIDCRedirectURL)
			if err != nil {
				return err
			}
			logger.Info().Str("redirect_url",
				redirectURL).Msg("Configured OpenID Connect redirect URL from the environment")
			config.OIDCRedirectURL = redirectURL
		}

		// Parse the provided URLs to ensure they are valid
		if config.OIDCIssuerURL != "" {
			var issuerURL *url.URL
			issuerURL, err = url.Parse(config.OIDCIssuerURL)
			if err != nil {
				return err
			}
			config.OIDCIssuerURL = issuerURL.String()
		}
		if config.OIDCRedirectURL != "" {
			var redirectURL *url.URL
			redirectURL, err = url.Parse(config.OIDCRedirectURL)
			if err != nil {
				return err
			}

			redirectURL, err = url.Parse(redirectURL.Scheme +
				"://" + net.JoinHostPort(redirectURL.Hostname(), config.Port))
			if err != nil {
				return err
			}
			config.OIDCRedirectURL = redirectURL.String()
		}
	}

	if config.IRODSEnvFilePath == "" {
		path := LookupIRODSEnvFilePath()
		if path == "" {
			logger.Error().
				Msg("Failed to find the iRODS environment file path from the environment")
		} else {
			logger.Info().
				Str("path", path).
				Msg("Configured iRODS environment file path from the environment")
		}
		config.IRODSEnvFilePath = path
	}

	if config.Host == "" {
		return fmt.Errorf("server config %w: address", ErrMissingArgument)
	}
	if config.Port == "" {
		return fmt.Errorf("server config %w: port", ErrMissingArgument)
	}
	if config.CertFilePath == "" {
		return fmt.Errorf("server config %w: certificate file path", ErrMissingArgument)
	}
	if config.KeyFilePath == "" {
		return fmt.Errorf("server config %w: key file path", ErrMissingArgument)
	}
	if config.IRODSEnvFilePath == "" {
		return fmt.Errorf("server config %w: iRODS environment file path", ErrMissingArgument)
	}
	if !(config.IndexInterval > 0) {
		return fmt.Errorf("server config %w: index interval", ErrMissingArgument)
	}

	return err
}

func getEnv(envVar string) (string, error) {
	val := os.Getenv(envVar)
	if val == "" {
		return "", fmt.Errorf("server config %w: %s",
			ErrEnvironmentVariableNotSet, envVar)
	}
	return val, nil
}

// iRODSUsernameFromEmail extracts an iRODS username from an email address. This assumes
// that the email address is in the form "username@domain", which is the case for
// Sanger users authenticated via OpenID Connect. If the email address cannot be parsed,
// an empty string is returned.
func iRODSUsernameFromEmail(logger zerolog.Logger, email string) string {
	address, err := mail.ParseAddress(email)
	if err != nil {
		logger.Err(err).Msg("Failed to parse user email address")
		return ""
	}
	return strings.Split(address.Address, "@")[0]
}

func writeErrorResponse(logger zerolog.Logger, w http.ResponseWriter, code int,
	message ...string) {
	var msg string
	if len(message) > 1 {
		msg = strings.Join(message, " ")
	}
	if msg == "" {
		msg = http.StatusText(code)
	}

	logger.Trace().
		Int("code", code).
		Str("msg", msg).
		Msg("Sending HTTP error")

	http.Error(w, msg, code)
}

// queryAtIntervals runs a query at regular intervals until the context is cancelled.
func queryAtIntervals(logger zerolog.Logger, ctx context.Context,
	interval time.Duration, queryFn func() ([]Item, error)) <-chan []Item {
	itemChan := make(chan []Item)

	findTick := time.NewTicker(interval)

	go func() {
		defer close(itemChan)
		defer findTick.Stop()

		for {
			select {
			case <-findTick.C:
				start := time.Now()
				items, err := queryFn()

				// If the query failed, do not use its runtime to adjust the interval
				if err != nil {
					logger.Err(err).Msg("Query failed")
					continue
				}

				itemChan <- items
				elapsed := time.Since(start)
				logger.Debug().Dur("elapsed", elapsed).Msg("Query completed")

				if elapsed > interval {
					logger.Warn().
						Dur("elapsed", elapsed).
						Dur("interval", interval).
						Msg("Query took longer than interval")
				}
			case <-ctx.Done():
				logger.Info().Msg("Query cancelled")
				return
			}
		}
	}()

	return itemChan
}
