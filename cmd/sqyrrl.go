package main

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"io"
	"os"
	"time"

	logs "github.com/wtsi-npg/logshim"
	"github.com/wtsi-npg/logshim-zerolog/zlog"

	"sqyrrl/internal"
	"sqyrrl/internal/server"
)

const defaultIRODSEnvFile = "~/.irods/irods_environment.json"
const iRODSEnvFileEnvVar = "IRODS_ENVIRONMENT_FILE"

type cliLoggingFlags struct {
	debug   bool // Enable debug logging
	verbose bool // Enable verbose logging
}

type httpServerFlags struct {
	addr        string // Address to listen on
	envFilePath string // Path to the iRODS environment file
}

var logFlags = cliLoggingFlags{}
var serverFlags = httpServerFlags{}

func setupLogger(flags *cliLoggingFlags) logs.Logger {
	var level logs.Level
	if flags.debug {
		level = logs.DebugLevel
	} else if flags.verbose {
		level = logs.InfoLevel
	} else {
		level = logs.ErrorLevel
	}

	// Choose a Zerolog logging backend
	var writer io.Writer
	if term.IsTerminal(int(os.Stdout.Fd())) {
		writer = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	} else {
		writer = os.Stderr
	}

	// Synchronize writes to the global logger
	logger := zlog.New(zerolog.SyncWriter(writer), level)

	return logs.InstallLogger(logger)
}

// getIRODSEnvFilePath returns the path to the iRODS environment file. If the path
// is not set in the environment, the default path is returned.
func getIRODSEnvFilePath() string {
	env := os.Getenv(iRODSEnvFileEnvVar)
	if env == "" {
		env = defaultIRODSEnvFile
	}
	return env
}

func printHelp(cmd *cobra.Command, args []string) {
	setupLogger(&logFlags)
	if err := cmd.Help(); err != nil {
		logs.GetLogger().Error().Err(err).Msg("help command failed")
		os.Exit(1)
	}
}

func startServer(cmd *cobra.Command, args []string) {
	setupLogger(&logFlags)
	server.Start(server.Params{
		Addr:        serverFlags.addr,
		EnvFilePath: serverFlags.envFilePath,
	})
}

func main() {
	rootCmd := &cobra.Command{
		Use:     "sqyrrl",
		Short:   "Sqyrrl.",
		Run:     printHelp,
		Version: internal.Version,
	}

	rootCmd.PersistentFlags().BoolVar(&logFlags.debug, "debug", false,
		"enable debug output")
	rootCmd.PersistentFlags().BoolVar(&logFlags.verbose, "verbose", false,
		"enable verbose output")
	rootCmd.SetVersionTemplate(`{{printf "%s\n" .Version}}`)

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the server",
		Long:  "Start the server.",
		Run:   startServer,
	}

	startCmd.Flags().StringVar(&serverFlags.addr, "addr", "127.0.0.1:8080",
		"Address on which to listen")
	startCmd.Flags().StringVar(&serverFlags.envFilePath, "irods-env",
		getIRODSEnvFilePath(),
		"Path to the iRODS environment file")

	rootCmd.AddCommand(startCmd)

	if err := rootCmd.Execute(); err != nil {
		setupLogger(&logFlags)
		logs.GetLogger().Err(err).Msg("command failed")
		os.Exit(1)
	}
}
