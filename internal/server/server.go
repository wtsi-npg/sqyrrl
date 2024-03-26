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
	"fmt"
	"github.com/cyverse/go-irodsclient/irods/util"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/microcosm-cc/bluemonday"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"

	"sqyrrl/internal"
)

var (
	tpl             *template.Template
	userInputPolicy *bluemonday.Policy
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	userInputPolicy = bluemonday.StrictPolicy()
}

type ContextKey string

// HandlerChain is a function that takes an http.Handler and returns an new http.Handler
// wrapping the input handler. Each handler in the chain should process the request in
// some way, and then call the next handler. Ideally, the functionality of each handler
// should be orthogonal to the others.
//
// This is sometimes called "middleware" in Go. I don't use that term because it already
// has an established meaning in the context of operating systems and networking:
// https://en.wikipedia.org/wiki/Middleware
type HandlerChain func(http.Handler) http.Handler

const AppName = "sqyrrl"

const correlationIDKey = ContextKey("correlation_id")

// SqyrrlServer is an HTTP server which contains an embedded iRODS client.
type SqyrrlServer struct {
	http.Server
	context context.Context     // Context for clean shutdown
	logger  zerolog.Logger      // Base logger from which the server creates its own subloggers
	account *types.IRODSAccount // iRODS account for the embedded client
}

type Config struct {
	Host         string
	Port         int
	EnvFilePath  string // Path to the iRODS environment file
	CertFilePath string
	KeyFilePath  string
}

// NewSqyrrlServer creates a new SqyrrlServer instance.
//
// This constructor sets up an iRODS account and configures routing for the server.
// The server is not started by this function. Call Start() on the returned server to
// start it. To stop the server, send SIGINT or SIGTERM to the process to trigger a
// graceful shutdown.
//
// Arguments:
//
//	logger: A zerolog logger instance. Normally this should be the root logger of the
//	        application. The server will create sub-loggers for its components.
//	config: Configuration for the server.
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

	// The sub-logger adds "hostname and" "component" field to the log entries. Further
	// fields are added by other components e.g. in the HTTP handlers.
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	sublogger := logger.With().
		Str("hostname", hostname).
		Str("component", "server").Logger()

	addr := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	mux := http.NewServeMux()
	account, err := getIRODSAccount(sublogger, config.EnvFilePath)
	if err != nil {
		logger.Err(err).Msg("Failed to get an iRODS account")
		return nil, err
	}

	serverCtx, cancelServer := context.WithCancel(context.Background())
	server := &SqyrrlServer{
		http.Server{
			Addr:    addr,
			Handler: mux,
			BaseContext: func(listener net.Listener) context.Context {
				return serverCtx
			}},
		serverCtx,
		sublogger,
		account,
	}

	server.setUpSignalHandler(cancelServer)
	server.addRoutes(mux)

	return server, nil
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

// addRequestLogger adds an HTTP request logger to the handler chain.
//
// If a correlation ID is present in the request context, it is logged.
func addRequestLogger(logger zerolog.Logger) HandlerChain {
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
				Str("forwarded_for", r.Header.Get(HTTPForwardedFor)).
				Str("user_agent", r.UserAgent()).
				Msg("Request served")
		})
		return lh(ah(next))
	}
}

// addCorrelationID adds a correlation ID to the request context and response headers.
func addCorrelationID(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var corrID string
			if corrID = r.Header.Get(HTTPHeaderCorrelationID); corrID == "" {
				corrID = xid.New().String()
				logger.Trace().
					Str("correlation_id", corrID).
					Str("url", r.URL.RequestURI()).
					Msg("Creating a new correlation ID")
				w.Header().Add(HTTPHeaderCorrelationID, corrID)
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

// handleHomePage is a handler for the static home page.
func handleHomePage(logger zerolog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Trace().Msg("HomeHandler called")

		type customData struct {
			Version string
		}

		data := customData{Version: internal.Version}

		tplName := "home.gohtml"
		if err := tpl.ExecuteTemplate(w, tplName, data); err != nil {
			logger.Err(err).
				Str("tplName", tplName).
				Msg("Failed to execute HTML template")
		}
	})
}

func handleIRODSGet(logger zerolog.Logger, account *types.IRODSAccount) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Trace().Msg("iRODS get handler called")

		if !r.URL.Query().Has(HTTPParamPath) {
			w.WriteHeader(http.StatusBadRequest)
			writeResponse(w, fmt.Sprintf("Error: '%s' parameter is missing\n",
				HTTPParamPath))
			return
		}

		var corrID string
		if val := r.Context().Value(correlationIDKey); val != nil {
			corrID = val.(string)
		}

		dirtyPath := r.URL.Query().Get(HTTPParamPath)
		cleanPath := userInputPolicy.Sanitize(dirtyPath)
		if cleanPath != dirtyPath {
			logger.Warn().
				Str("correlation_id", corrID).
				Str("clean_path", cleanPath).
				Str("dirty_path", dirtyPath).
				Msg("Path was sanitised")
		}

		rodsLogger := logger.With().
			Str("correlation_id", corrID).
			Str("irods", "get").Logger()
		getFileRange(rodsLogger, w, r, account, cleanPath)
	})
}

func writeResponse(writer http.ResponseWriter, message string) {
	if _, err := io.WriteString(writer, message); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}
