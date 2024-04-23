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
	"html/template"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "crypto/tls" // Leave this to ensure that the TLS package is linked

	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/icommands"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/go-irodsclient/irods/util"
	"github.com/microcosm-cc/bluemonday"
	"github.com/rs/zerolog"
)

type ContextKey string

// SqyrrlServer is an HTTP server which contains an embedded iRODS client.
type SqyrrlServer struct {
	http.Server
	context       context.Context                        // Context for clean shutdown
	logger        zerolog.Logger                         // Base logger from which the server creates its own sub-loggers
	manager       *icommands.ICommandsEnvironmentManager // iRODS manager for the embedded client
	account       *types.IRODSAccount                    // iRODS account for the embedded client
	indexInterval time.Duration                          // Interval for indexing items
	index         *ItemIndex                             // ItemIndex of items in the iRODS server
}

type Config struct {
	Host          string
	Port          string
	EnvFilePath   string // Path to the iRODS environment file
	CertFilePath  string
	KeyFilePath   string
	IndexInterval time.Duration
}

const AppName = "sqyrrl"

const MinIndexInterval = 10 * time.Second
const DefaultIndexInterval = 60 * time.Second

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
func NewSqyrrlServer(logger zerolog.Logger, config Config) (*SqyrrlServer, error) {
	if config.Host == "" {
		return nil, errors.New("missing host")
	}
	if config.Port == "" {
		return nil, errors.New("missing port")
	}
	if config.CertFilePath == "" {
		return nil,
			errors.New("missing certificate file path")
	}

	indexInterval := config.IndexInterval
	if indexInterval < MinIndexInterval {
		logger.Warn().
			Dur("interval", indexInterval).
			Dur("min_interval", MinIndexInterval).
			Msg("Index interval too short, using the default interval")
		indexInterval = DefaultIndexInterval
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

	addr := net.JoinHostPort(config.Host, config.Port)
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
		indexInterval,
		NewItemIndex([]Item{}),
	}

	server.setUpIndexing(serverCtx)
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

func (server *SqyrrlServer) setUpIndexing(ctx context.Context) {
	logger := server.logger

	filesystem, err := fs.NewFileSystemWithDefault(server.account, AppName)
	if err != nil {
		panic(err)
	}

	// Query the iRODS server for items at regular intervals
	items := queryAtIntervalsWithBackoff(logger, ctx, server.indexInterval,
		func() ([]Item, error) {
			return findItems(filesystem)
		})

	logger.Info().Dur("interval", server.indexInterval).Msg("Indexing started")

	// Create an index of items
	go func() {
		for {
			select {
			case <-ctx.Done():
				logger.Info().Msg("Indexing cancelled")
				return
			case items := <-items:
				server.index.items = items
				logger.Info().
					Str("index", server.index.String()).
					Msg("Updated index")
			}
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

func ConfigureAndStart(logger zerolog.Logger, config Config) {
	if config.Host == "" {
		logger.Error().Msg("Missing host component of address to listen on")
		return
	}
	if config.Port == "" {
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
	if !(config.IndexInterval > 0) {
		logger.Error().Msg("Missing index interval")
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

// queryAtIntervalsWithBackoff runs a query at regular intervals until the context is
// cancelled.
//
// If the query takes longer than the interval, the next query is delayed by
// the time taken by the previous query. If the query takes less time than the interval
// by a certain factor, the interval is shrunk to that value, but not below the original.
func queryAtIntervalsWithBackoff(logger zerolog.Logger, ctx context.Context,
	interval time.Duration, queryFn func() ([]Item, error)) chan []Item {
	items := make(chan []Item)

	origInterval := interval
	shrinkFactor := 0.7
	findTick := time.NewTicker(interval)

	go func() {
		defer close(items)
		defer findTick.Stop()

		for {
			select {
			case <-findTick.C:
				start := time.Now()
				x, err := queryFn()
				if err != nil {
					logger.Err(err).Msg("Query failed")
				} else {
					items <- x
				}

				elapsed := time.Since(start)

				// If the query took longer than the interval, back off by making the next
				// query wait for the extra amount of time in excess of the internal that
				// the last query took.
				if elapsed > interval {
					backoff := time.NewTimer(elapsed - interval)
					select {
					case <-backoff.C:
						// Continue to the next iteration
					case <-ctx.Done():
						logger.Info().Msg("Query cancelled")
						return
					}
				}
				// If the query took less time than the interval by the shrink factor,
				// shrink the interval to that value, but not below the original value.
				threshold := interval.Seconds() * shrinkFactor
				if elapsed.Seconds() < threshold {
					interval = time.Duration(math.Max(threshold, origInterval.Seconds()))
				}
			case <-ctx.Done():
				logger.Info().Msg("Query cancelled")
				return
			}
		}
	}()

	return items
}
