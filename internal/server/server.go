package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/cyverse/go-irodsclient/irods/util"
	logs "github.com/wtsi-npg/logshim"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/go-irodsclient/utils/icommands"
)

const AppName = "sqrrl"

// setupSignalHandler sets up a signal handler to cancel the context when a
// SIGINT or SIGTERM is received.
func setupSignalHandler(cancel context.CancelFunc) {
	log := logs.GetLogger()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-signals

		switch s {
		case syscall.SIGINT:
			log.Info().Msg("server got SIGINT, shutting down")
			cancel()
		case syscall.SIGTERM:
			log.Info().Msg("server got SIGTERM, shutting down")
			cancel()
		default:
			log.Error().Str("signal", s.String()).
				Msg("got unexpected signal, exiting")
			os.Exit(1)
		}
	}()
}

// getIRODSAccount returns an iRODS account instance using the iRODS environment for
// configuration. The environment file path is given by envFilePath. If the file
// is not readable, an error is returned.
func getIRODSAccount(envFilePath string) (*types.IRODSAccount, error) {
	log := logs.GetLogger()

	// At this point envFilePath is known to be non-empty

	mgr, err := icommands.CreateIcommandsEnvironmentManager()
	if err != nil {
		log.Err(err).Msg("failed to create an iRODS environment manager")
		return nil, err
	}

	// mgr.Load below will succeed even if the iRODS environment file does not exist,
	// but we absolutely don't want that behaviour here.
	fileInfo, err := os.Stat(envFilePath)
	if os.IsNotExist(err) {
		log.Err(err).Str("path", envFilePath).
			Msg("iRODS environment file does not exist")
		return nil, err
	}
	if fileInfo.IsDir() {
		ferr := errors.New("iRODS environment file is a directory")
		log.Err(ferr).Str("path", envFilePath).
			Msg("iRODS environment file is a directory")
		return nil, ferr
	}

	if err := mgr.SetEnvironmentFilePath(envFilePath); err != nil {
		log.Err(err).
			Str("path", envFilePath).
			Msg("failed to set the iRODS environment file path")
		return nil, err
	}

	if err := mgr.Load(os.Getpid()); err != nil {
		log.Err(err).
			Msg("the iRODS environment manager failed to load an environment")
		return nil, err
	}

	log.Info().Str("path", mgr.GetEnvironmentFilePath()).
		Msg("loaded iRODS environment file")

	account, err := mgr.ToIRODSAccount()
	if err != nil {
		log.Err(err).Msg("failed to obtain an iRODS account instance")
		return nil, err
	}

	log.Info().Str("host", account.Host).
		Int("port", account.Port).
		Str("zone", account.ClientZone).
		Str("user", account.ClientUser).
		Str("auth_scheme", string(account.AuthenticationScheme)).
		Msg("iRODS account obtained")

	return account, nil
}

func makeIRODSFileSystem(account *types.IRODSAccount) (*fs.FileSystem, error) {
	filesystem, err := fs.NewFileSystemWithDefault(account, AppName)
	if err != nil {
		logs.GetLogger().Err(err).Msg("failed to create an iRODS file system")
		return nil, err
	}

	return filesystem, nil
}

func writeResponse(writer http.ResponseWriter, message string) {
	if _, err := io.WriteString(writer, message); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		logs.GetLogger().Err(err).Msg("error writing response")
	}
}

func getFileRange(writer http.ResponseWriter, request *http.Request, account *types.IRODSAccount, path string) {
	filesystem, err := makeIRODSFileSystem(account)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		writeResponse(writer, "Error: iRODS access failed\n")
		return
	}

	defer filesystem.Release()

	if !filesystem.ExistsFile(path) {
		writer.WriteHeader(http.StatusNotFound)
		writeResponse(writer, fmt.Sprintf("Error: path not found '%s'\n", path))
		return
	}

	fh, err := filesystem.OpenFile(path, "", "r")
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		writeResponse(writer, fmt.Sprintf("Error: failed to open '%s'\n", path))
		return
	}

	defer func(fh *fs.FileHandle) {
		if err := fh.Close(); err != nil {
			logs.GetLogger().Err(err).Str("path", path).Msg("failed to close file handle")
		}
	}(fh)

	http.ServeContent(writer, request, path, time.Now(), fh)
}

func handleGet(account *types.IRODSAccount) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if !request.URL.Query().Has("path") {
			writer.WriteHeader(http.StatusBadRequest)
			writeResponse(writer, "Error: path parameter is missing\n")
			return
		}

		path := request.URL.Query().Get("path")
		logs.GetLogger().Info().Str("path", path).Msg("requested file")

		getFileRange(writer, request, account, path)
	}
}

func handleRoot(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
	writeResponse(writer, "Hello\n")
}

type Params struct {
	Addr        string // Address to listen on
	EnvFilePath string // Path to the iRODS environment file
}

func Start(params Params) {
	log := logs.GetLogger()

	if params.Addr == "" {
		log.Error().Msg("missing address to listen on")
		return
	}
	if params.EnvFilePath == "" {
		log.Error().Msg("missing iRODS environment file path")
		return
	}

	envFilePath, err := util.ExpandHomeDir(params.EnvFilePath)
	if err != nil {
		log.Err(err).Str("path", params.EnvFilePath).
			Msg("failed to expand the iRODS environment file path")
		return
	}

	account, err := getIRODSAccount(envFilePath)
	if err != nil {
		log.Err(err).Msg("failed to get an iRODS account")
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/get", handleGet(account))

	serverCtx, cancelServer := context.WithCancel(context.Background())
	setupSignalHandler(cancelServer)

	server := &http.Server{Addr: params.Addr, Handler: mux,
		BaseContext: func(listener net.Listener) context.Context {
			return serverCtx
		}}

	go func() {
		serr := server.ListenAndServe()
		log.Info().Msg("server stopped listening")

		if serr != nil {
			switch {
			case errors.Is(serr, http.ErrServerClosed):
				log.Info().Msg("server closed cleanly")
			default:
				log.Err(serr).Msg("server closed with an error")
			}
		}
	}()

	<-serverCtx.Done()

	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTimeout()

	if serr := server.Shutdown(timeoutCtx); serr != nil {
		log.Err(serr).Msg("error shutting down server")
	}
	log.Info().Msg("server shutdown cleanly")
}
