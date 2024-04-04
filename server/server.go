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
	"errors"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cyverse/go-irodsclient/icommands"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/go-irodsclient/irods/util"
	"github.com/microcosm-cc/bluemonday"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

type ContextKey string

// HandlerChain is a function that takes an http.Handler and returns an new http.Handler
// wrapping the input handler. Each handler in the chain should process the request in
// some way, and then call the next handler. Ideally, the functionality of each handler
// should be orthogonal to the others.
//
// This is sometimes called "middleware" in Go. I haven't used that term here because it
// already has an established meaning in the context of operating systems and networking.
type HandlerChain func(http.Handler) http.Handler

// SqyrrlServer is an HTTP server which contains an embedded iRODS client.
type SqyrrlServer struct {
	http.Server
	context context.Context                        // Context for clean shutdown
	logger  zerolog.Logger                         // Base logger from which the server creates its own sub-loggers
	manager *icommands.ICommandsEnvironmentManager // iRODS manager for the embedded client
	account *types.IRODSAccount                    // iRODS account for the embedded client
}

type Config struct {
	Host         string
	Port         int
	EnvFilePath  string // Path to the iRODS environment file
	CertFilePath string
	KeyFilePath  string
}

const AppName = "sqyrrl"

const correlationIDKey = ContextKey("correlation_id")

var userInputPolicy = bluemonday.StrictPolicy()

var (
	compileOnce sync.Once
	templates   *template.Template
)

// GetTemplates returns the HTML templates for the server.
//
// This exists to allow the tests to load the templates more easily from the context of
// the test subdirectory. This function must be called once in test suite setup,
// with the working directory set to the root of the project, to load the templates.
// After that, it may be called freely in any context to access the loaded templates.
func GetTemplates() *template.Template {
	compileOnce.Do(func() {
		templates = template.Must(template.ParseGlob("templates/*"))
	})
	return templates
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
func NewSqyrrlServer(logger zerolog.Logger, config Config) (*SqyrrlServer, error) {
	if config.Host == "" {
		return nil, errors.New("missing host")
	}
	if config.Port == 0 {
		return nil, errors.New("missing port")
	}
	if config.CertFilePath == "" {
		return nil,
			errors.New("missing certificate file path")
	}

	// The sub-suiteLogger adds "hostname and" "component" field to the log entries. Further
	// fields are added by other components e.g. in the HTTP handlers.
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	subLogger := logger.With().
		Str("hostname", hostname).
		Str("component", "server").Logger()

	manager, err := NewICommandsEnvironmentManager()
	if err != nil {
		logger.Err(err).Msg("failed to create an iRODS environment manager")
		return nil, err
	}

	if err := manager.SetEnvironmentFilePath(config.EnvFilePath); err != nil {
		subLogger.Err(err).
			Str("path", config.EnvFilePath).
			Msg("Failed to set the iRODS environment file path")
		return nil, err
	}

	account, err := NewIRODSAccount(subLogger, manager)
	if err != nil {
		logger.Err(err).Msg("Failed to get an iRODS account")
		return nil, err
	}

	addr := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	mux := http.NewServeMux()
	serverCtx, cancelServer := context.WithCancel(context.Background())

	server := &SqyrrlServer{
		http.Server{
			Addr:    addr,
			Handler: mux,
			BaseContext: func(listener net.Listener) context.Context {
				return serverCtx
			}},
		serverCtx,
		subLogger,
		manager,
		account,
	}

	server.setUpSignalHandler(cancelServer)
	server.addRoutes(mux)

	return server, nil
}

func (server *SqyrrlServer) IRODSEnvFilePath() string {
	return server.manager.GetEnvironmentFilePath()
}

func (server *SqyrrlServer) IRODSAuthFilePath() string {
	return server.manager.GetPasswordFilePath()
}

func (server *SqyrrlServer) Start(certFile string, keyFile string) {
	go func() {
		logger := server.logger

		err := server.ListenAndServeTLS(certFile, keyFile)

		logger.Info().Msg("Server stopped listening")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrServerClosed):
				logger.Info().Msg("Server closed cleanly")
			default:
				logger.Err(err).Msg("Server closed with an error")
			}
		}
	}()
	<-server.context.Done()

	server.waitAndShutdown()
}

func ConfigureAndStart(logger zerolog.Logger, config Config) {
	if config.Host == "" {
		logger.Error().Msg("Missing host component of address to listen on")
		return
	}
	if config.Port == 0 {
		logger.Error().Msg("Missing port component of address to listen on")
		return
	}
	if config.CertFilePath == "" {
		logger.Error().Msg("Missing certificate file path")
		return
	}
	if config.KeyFilePath == "" {
		logger.Error().Msg("Missing key file path")
		return
	}
	if config.EnvFilePath == "" {
		logger.Error().Msg("Missing iRODS environment file path")
		return
	}

	envFilePath, err := util.ExpandHomeDir(config.EnvFilePath)
	if err != nil {
		logger.Err(err).Str("path", config.EnvFilePath).
			Msg("Failed to expand the iRODS environment file path")
		return
	}
	config.EnvFilePath = envFilePath

	server, err := NewSqyrrlServer(logger, config)
	if err != nil {
		logger.Err(err).Msg("Failed to create a server")
		return
	}

	server.Start(config.CertFilePath, config.KeyFilePath)
}

func (server *SqyrrlServer) setUpSignalHandler(cancel context.CancelFunc) {
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
			cancel()
		default:
			logger.Warn().
				Str("signal", sig.String()).
				Msg("Received signal")
		}
	}()
}

func (server *SqyrrlServer) waitAndShutdown() {
	logger := server.logger

	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTimeout()

	if err := server.Shutdown(timeoutCtx); err != nil {
		logger.Err(err).Msg("Error shutting down server")
	}
	logger.Info().Msg("Server shutdown cleanly")
}

// AddRequestLogger adds an HTTP request suiteLogger to the handler chain.
//
// If a correlation ID is present in the request context, it is logged.
func AddRequestLogger(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
		lh := hlog.NewHandler(logger)

		ah := hlog.AccessHandler(func(r *http.Request, status, size int, dur time.Duration) {
			var corrID string
			if val := r.Context().Value(correlationIDKey); val != nil {
				corrID = val.(string)
			}

			hlog.FromRequest(r).Info().
				Str("correlation_id", corrID).
				Dur("duration", dur).
				Int("size", size).
				Int("status", status).
				Str("method", r.Method).
				Str("url", r.URL.RequestURI()).
				Str("remote_addr", r.RemoteAddr).
				Str("forwarded_for", r.Header.Get(HeaderForwardedFor)).
				Str("user_agent", r.UserAgent()).
				Msg("Request served")
		})
		return lh(ah(next))
	}
}

// AddCorrelationID adds a correlation ID to the request context and response headers.
func AddCorrelationID(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var corrID string
			if corrID = r.Header.Get(HeaderCorrelationID); corrID == "" {
				corrID = xid.New().String()
				logger.Trace().
					Str("correlation_id", corrID).
					Str("url", r.URL.RequestURI()).
					Msg("Creating a new correlation ID")
				w.Header().Add(HeaderCorrelationID, corrID)
			} else {
				logger.Trace().
					Str("correlation_id", corrID).
					Str("url", r.URL.RequestURI()).
					Msg("Using correlation ID from request")
			}

			ctx := context.WithValue(r.Context(), correlationIDKey, corrID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeErrorResponse(logger zerolog.Logger, w http.ResponseWriter, code int, message ...string) {
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
