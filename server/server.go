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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "crypto/tls" // Leave this to ensure that the TLS package is linked

	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/icommands"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/microcosm-cc/bluemonday"
	"github.com/rs/zerolog"
)

type ContextKey string

// SqyrrlServer is an HTTP server which contains an embedded iRODS client.
type SqyrrlServer struct {
	http.Server
	config  Config
	context context.Context                        // Context for clean shutdown
	cancel  context.CancelFunc                     // Cancel function for the server
	logger  zerolog.Logger                         // Base logger from which the server creates its own sub-loggers
	manager *icommands.ICommandsEnvironmentManager // iRODS manager for the embedded client
	account *types.IRODSAccount                    // iRODS account for the embedded client
	index   *ItemIndex                             // ItemIndex of items in the iRODS server
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

const (
	MinIndexInterval     = 10 * time.Second
	DefaultIndexInterval = 60 * time.Second
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
func NewSqyrrlServer(logger zerolog.Logger, config Config) (server *SqyrrlServer, err error) { // NRV
	if config.Host == "" {
		return nil, fmt.Errorf("server config %w: host", ErrMissingArgument)
	}
	if config.Port == "" {
		return nil, fmt.Errorf("server config %w: port", ErrMissingArgument)
	}
	if config.CertFilePath == "" {
		return nil,
			fmt.Errorf("server config %w: certificate file path", ErrMissingArgument)
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

	var manager *icommands.ICommandsEnvironmentManager
	if config.EnvFilePath == "" {
		config.EnvFilePath = LookupIRODSEnvFilePath()
	}

	logger.Debug().
		Str("host", config.Host).
		Str("port", config.Port).
		Str("cert_file", config.CertFilePath).
		Str("key_file", config.KeyFilePath).
		Str("irods_env", config.EnvFilePath).
		Str("cwd", cwd).
		Dur("index_interval", config.IndexInterval).Msg("Server configured")

	if manager, err = NewICommandsEnvironmentManager(subLogger, config.EnvFilePath); err != nil {
		logger.Err(err).Msg("Failed to create an iRODS environment manager")
		return nil, err
	}

	var account *types.IRODSAccount
	if account, err = NewIRODSAccount(subLogger, manager); err != nil {
		logger.Err(err).Msg("Failed to get an iRODS account")
		return nil, err
	}

	addr := net.JoinHostPort(config.Host, config.Port)
	mux := http.NewServeMux()
	serverCtx, cancelServer := context.WithCancel(context.Background())

	server = &SqyrrlServer{
		http.Server{
			Addr:    addr,
			Handler: mux,
			BaseContext: func(listener net.Listener) context.Context {
				return serverCtx
			}},
		config,
		serverCtx,
		cancelServer,
		subLogger,
		manager,
		account,
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
		Str("irods_env", config.EnvFilePath).
		Str("cwd", cwd).
		Dur("index_interval", config.IndexInterval).Msg("Server configured")

	return server, nil
}

func (server *SqyrrlServer) IRODSEnvFilePath() string {
	return server.manager.GetEnvironmentFilePath()
}

func (server *SqyrrlServer) IRODSAuthFilePath() string {
	return server.manager.GetPasswordFilePath()
}

// Start starts the server. This function blocks until the server is stopped.
//
// To stop the server, send SIGINT or SIGTERM to the process or call the server's Stop
// function directly from another goroutine. An error is returned if the server fails
// to start or if it fails to stop cleanly (with http.ErrServerClosed).
func (server *SqyrrlServer) Start() error {
	var serveErr, shutErr error

	go func() {
		logger := server.logger

		// The following make it easier to diagnose issues with missing files
		// given as relative paths. We don't abort on errors here because it's cleaner
		// to allow the server to try to start and clean up any resulting error in one
		// place.
		absCertFilePath, err := filepath.Abs(server.config.CertFilePath)
		if err != nil {
			logger.Err(err).
				Str("path", server.config.CertFilePath).
				Msg("Failed to get the absolute path of the certificate file")
		}
		absKeyFilePath, err := filepath.Abs(server.config.KeyFilePath)
		if err != nil {
			logger.Err(err).
				Str("path", server.config.KeyFilePath).
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
	filesystem, err = fs.NewFileSystemWithDefault(server.account, AppName)
	if err != nil {
		return err
	}

	// Query the iRODS server for items at regular intervals
	itemChan := queryAtIntervals(logger, server.context, server.config.IndexInterval,
		func() ([]Item, error) {
			return findItems(filesystem)
		})

	logger.Info().Dur("interval", server.config.IndexInterval).Msg("Indexing started")

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
				server.index.SetItems(items)
				logger.Info().
					Str("index", server.index.String()).
					Msg("Updated index")
			}
		}
	}()

	return nil
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

func ConfigureAndStart(logger zerolog.Logger, config Config) error {
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
	if !(config.IndexInterval > 0) {
		return fmt.Errorf("server config %w: index interval", ErrMissingArgument)
	}

	var server *SqyrrlServer
	server, err := NewSqyrrlServer(logger, config)
	if err != nil {
		return err
	}

	return server.Start()
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
