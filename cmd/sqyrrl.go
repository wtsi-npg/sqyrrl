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

package cmd

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/alexedwards/scs/v2"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"sqyrrl/server"
)

var mainLogger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})

type cliFlags struct {
	certFilePath   string // Path to the certificate file
	keyFilePath    string // Path to the key file
	envFilePath    string // Path to the iRODS environment file
	configFilePath string // Path to a TOML configuration file

	host  string // Address to listen on, host part
	level string // Logging level
	port  string // Port to listen on

	indexInterval time.Duration // Interval to index files

	enableOIDC bool // Enable OpenID Connect authentication
}

var cliFlagsSelected = cliFlags{}

// configureRootLogger configures the root logger for the application. It sets up common
// fields for the application name, version, and process ID, and it sets the default log
// level.
//
// Previously we've created a logger interface to avoid direct dependency on any of the
// available logging libraries. However, experience has shown that we never actually
// switch logging libraries, so the interface is not needed. We've used Zerolog for a few
// years now, and it's been great. Without the interface, we can more easily take
// advantage of Zerolog's features, particularly support for HTTP request logging.
func configureRootLogger(flags *cliFlags) zerolog.Logger {
	var level zerolog.Level

	switch strings.ToLower(flags.level) {
	case "trace":
		level = zerolog.TraceLevel
	case "debug":
		level = zerolog.DebugLevel
	case "info":
		level = zerolog.InfoLevel
	case "warn":
		level = zerolog.WarnLevel
	case "error":
		level = zerolog.ErrorLevel
	default:
		level = zerolog.InfoLevel
	}

	var writer io.Writer
	if term.IsTerminal(int(os.Stdout.Fd())) {
		writer = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	} else {
		writer = os.Stderr
	}

	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	return zerolog.New(zerolog.SyncWriter(writer)).With().
		Timestamp().
		Str("app", server.AppName).
		Str("version", server.Version).
		Int("pid", os.Getpid()).
		Logger().Level(level)
}

func checkLogLevelValue(cmd *cobra.Command, args []string) {
	levelFlag := cliFlagsSelected.level
	if levelFlag != "" {
		for _, level := range []string{"trace", "debug", "info", "warn", "error"} {
			if strings.EqualFold(levelFlag, level) {
				cliFlagsSelected.level = level
				return
			}
		}
		err := fmt.Errorf("invalid log level: '%s'", levelFlag)
		mainLogger.Err(err).Msg("Invalid log level")
		os.Exit(1)
	}
}

func printHelp(cmd *cobra.Command, args []string) {
	if err := cmd.Help(); err != nil {
		mainLogger.Error().Err(err).Msg("Help command failed")
		os.Exit(1)
	}
}

func startServer(cmd *cobra.Command, args []string) (err error) { // NRV
	logger := configureRootLogger(&cliFlagsSelected)

	var config server.Config
	if cliFlagsSelected.configFilePath != "" {
		var tomlData []byte
		if tomlData, err = os.ReadFile(cliFlagsSelected.configFilePath); err != nil {
			return err
		}

		_, err = toml.Decode(string(tomlData), &config)
		if err != nil {
			return err
		}
		logger.Info().Str("path", cliFlagsSelected.configFilePath).
			Str("config", fmt.Sprintf("%v", config)).Msg("Config loaded")
		config.ConfigFilePath = cliFlagsSelected.configFilePath
	}

	if cliFlagsSelected.host != "" {
		config.Host = cliFlagsSelected.host
		logger.Info().Str("host", config.Host).Msg(
			"Configured host overridden on command line")
	}
	if cliFlagsSelected.port != "" {
		config.Port = cliFlagsSelected.port
		logger.Info().Str("port", config.Port).Msg(
			"Configured port overridden on command line")
	}
	if cliFlagsSelected.certFilePath != "" {
		config.CertFilePath = cliFlagsSelected.certFilePath
		logger.Info().Str("path", config.CertFilePath).Msg(
			"Configured certificate file path overridden on command line")
	}
	if cliFlagsSelected.keyFilePath != "" {
		config.KeyFilePath = cliFlagsSelected.keyFilePath
		logger.Info().Str("path", config.KeyFilePath).Msg(
			"Configured key file path overridden on command line")
	}
	if cliFlagsSelected.envFilePath != "" {
		config.IRODSEnvFilePath = cliFlagsSelected.envFilePath
		logger.Info().Str("path", config.IRODSEnvFilePath).Msg(
			"Configured iRODS environment file path overridden on command line")
	}
	if cliFlagsSelected.enableOIDC {
		config.EnableOIDC = cliFlagsSelected.enableOIDC
		logger.Info().Bool("enabled", config.EnableOIDC).Msg(
			"Configured OpenID Connect authentication overridden on command line")
	}
	if cliFlagsSelected.indexInterval != 0 {
		config.IndexInterval = cliFlagsSelected.indexInterval
		logger.Info().Dur("interval", config.IndexInterval).Msg(
			"Configured index interval overridden on command line")
	}

	err = server.Configure(logger, &config)
	if err != nil {
		return err
	}

	// Server-side storage of session data, keyed on a random session ID exchanged with
	// the client
	sessManager := scs.New()
	sessManager.Cookie.Name = "sqyrrl-session"         // Session cookie name
	sessManager.Cookie.HttpOnly = true                 // Don't let JS access the cookie
	sessManager.Cookie.Persist = false                 // Don't allow the session to persist across browser sessions
	sessManager.Cookie.SameSite = http.SameSiteLaxMode // Can't use Strict because of the OAuth2 callback
	sessManager.Cookie.Secure = true                   // Require HTTPS because SameSite can't be Strict
	sessManager.Lifetime = 10 * time.Minute            // Session lifetime

	var srv *server.SqyrrlServer
	srv, err = server.NewSqyrrlServer(logger, &config, sessManager)
	if err != nil {
		return err
	}

	err = srv.Start()
	if err != nil {
		return err
	}

	return err
}

func CLI() {
	rootCmd := &cobra.Command{
		Use:              "sqyrrl",
		Short:            "Sqyrrl.",
		PersistentPreRun: checkLogLevelValue,
		Run:              printHelp,
		Version:          server.Version,
	}
	rootCmd.PersistentFlags().StringVar(&cliFlagsSelected.level,
		"log-level", "info",
		"Set the log level (trace, debug, info, warn, error)")
	rootCmd.SetVersionTemplate(`{{printf "%s\n" .Version}}`)

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Configure and start the server",
		Long:  "Configure and start the server.",
		RunE:  startServer,
	}
	startCmd.Flags().StringVar(&cliFlagsSelected.host,
		"host", "",
		"Address on which to listen, host part")
	startCmd.Flags().StringVar(&cliFlagsSelected.port,
		"port", "",
		"Port on which to listen")
	startCmd.Flags().StringVar(&cliFlagsSelected.certFilePath,
		"cert-file", "",
		"Path to the SSL certificate file")
	startCmd.Flags().StringVar(&cliFlagsSelected.keyFilePath,
		"key-file", "",
		"Path to the SSL private key file")
	startCmd.Flags().StringVar(&cliFlagsSelected.envFilePath,
		"irods-env", "",
		"Path to the iRODS environment file")
	startCmd.Flags().StringVar(&cliFlagsSelected.configFilePath,
		"config", "",
		"Path to a TOML configuration file")
	startCmd.Flags().DurationVar(&cliFlagsSelected.indexInterval,
		"index-interval", server.DefaultIndexInterval,
		"Interval at which update the index")
	startCmd.Flags().BoolVar(&cliFlagsSelected.enableOIDC,
		"enable-oidc", false,
		"Enable OpenID Connect authentication")

	rootCmd.AddCommand(startCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
