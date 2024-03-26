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
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/icommands"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/rs/zerolog"
)

const defaultIRODSEnvFile = "~/.irods/irods_environment.json"
const iRODSEnvFileEnvVar = "IRODS_ENVIRONMENT_FILE"

// GetIRODSEnvFilePath returns the path to the iRODS environment file. If the path
// is not set in the environment, the default path is returned.
func GetIRODSEnvFilePath() string {
	env := os.Getenv(iRODSEnvFileEnvVar)
	if env == "" {
		env = defaultIRODSEnvFile
	}
	return env
}

// getIRODSAccount returns an iRODS account instance using the iRODS environment for
// configuration. The environment file path is given by envFilePath. If the file
// is not readable, an error is returned.
func getIRODSAccount(logger zerolog.Logger,
	envFilePath string) (*types.IRODSAccount, error) {
	// At this point envFilePath is known to be non-empty
	mgr, err := icommands.CreateIcommandsEnvironmentManager()
	if err != nil {
		logger.Err(err).Msg("failed to create an iRODS environment manager")
		return nil, err
	}

	// mgr.Load below will succeed even if the iRODS environment file does not exist,
	// but we absolutely don't want that behaviour here.
	fileInfo, err := os.Stat(envFilePath)
	if os.IsNotExist(err) {
		logger.Err(err).Str("path", envFilePath).
			Msg("iRODS environment file does not exist")
		return nil, err
	}
	if fileInfo.IsDir() {
		ferr := errors.New("iRODS environment file is a directory")
		logger.Err(ferr).Str("path", envFilePath).
			Msg("iRODS environment file is a directory")
		return nil, ferr
	}

	if err := mgr.SetEnvironmentFilePath(envFilePath); err != nil {
		logger.Err(err).
			Str("path", envFilePath).
			Msg("Failed to set the iRODS environment file path")
		return nil, err
	}

	if err := mgr.Load(os.Getpid()); err != nil {
		logger.Err(err).
			Msg("iRODS environment manager failed to load an environment")
		return nil, err
	}

	logger.Info().Str("path", mgr.GetEnvironmentFilePath()).
		Msg("Loaded iRODS environment file")

	account, err := mgr.ToIRODSAccount()
	if err != nil {
		logger.Err(err).Msg("Failed to obtain an iRODS account instance")
		return nil, err
	}

	logger.Info().Str("host", account.Host).
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
		return nil, err
	}

	return filesystem, nil
}

func getFileRange(logger zerolog.Logger,
	writer http.ResponseWriter,
	request *http.Request,
	account *types.IRODSAccount, path string) {
	filesystem, err := makeIRODSFileSystem(account)
	if err != nil {
		logger.Err(err).Msg("Failed to create an iRODS file system")

		writer.WriteHeader(http.StatusInternalServerError)
		writeResponse(writer, "Error: iRODS access failed\n")
		return
	}

	defer filesystem.Release()

	if !filesystem.ExistsFile(path) {
		logger.Info().Str("path", path).Msg("Requested path does not exist")

		writer.WriteHeader(http.StatusNotFound)
		writeResponse(writer, fmt.Sprintf("Error: path not found '%s'\n", path))
		return
	}

	fh, err := filesystem.OpenFile(path, "", "r")
	if err != nil {
		logger.Err(err).Str("path", path).Msg("Failed to open file")

		writer.WriteHeader(http.StatusInternalServerError)
		writeResponse(writer, fmt.Sprintf("Error: failed to open '%s'\n", path))
		return
	}

	defer func(fh *fs.FileHandle) {
		if err := fh.Close(); err != nil {
			logger.Err(err).Str("path", path).
				Msg("Failed to close file handle")
		}
	}(fh)

	logger.Info().Str("path", path).Msg("Serving file")
	http.ServeContent(writer, request, path, time.Now(), fh)
}
