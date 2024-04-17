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
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/icommands"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/go-irodsclient/irods/util"
	"github.com/rs/zerolog"
)

const defaultIRODSEnvFile = "~/.irods/irods_environment.json"
const iRODSEnvFileEnvVar = "IRODS_ENVIRONMENT_FILE"

const PublicUser = "public"

// IRODSEnvFilePath returns the path to the iRODS environment file. If the path
// is not set in the environment, the default path is returned.
func IRODSEnvFilePath() string {
	path := os.Getenv(iRODSEnvFileEnvVar)
	if path == "" {
		path = defaultIRODSEnvFile
	}
	path = filepath.Clean(path)

	envRoot, err := os.UserHomeDir()
	if err != nil {
		envRoot = "."
	}
	if path[0] == '~' {
		path = envRoot + path[1:]
	}

	return path
}

// InitIRODS initialises the iRODS environment by creating a populated auth file if it
// does not already exist. This avoids the need to have `iinit` present on the server
// host.
func InitIRODS(logger zerolog.Logger, manager *icommands.ICommandsEnvironmentManager, password string) error {
	authFile := manager.GetPasswordFilePath()
	if _, err := os.Stat(authFile); err != nil && errors.Is(err, os.ErrNotExist) {
		logger.Info().
			Str("path", authFile).
			Msg("Creating an iRODS auth file because one does not exist")
		return icommands.EncodePasswordFile(authFile, password, os.Getuid())
	}
	return nil
}

// NewICommandsEnvironmentManager creates a new environment manager instance.
//
// This function is just for aesthetic purposes, to fit with the convention of naming
// functions creating something with "New".
func NewICommandsEnvironmentManager() (*icommands.ICommandsEnvironmentManager, error) {
	return icommands.CreateIcommandsEnvironmentManager()
}

// NewIRODSAccount returns an iRODS account instance using the iRODS environment for
// configuration. The environment file path is obtained from the manager.
func NewIRODSAccount(logger zerolog.Logger,
	manager *icommands.ICommandsEnvironmentManager) (*types.IRODSAccount, error) {
	// manager.Load() below will succeed even if the iRODS environment file does not
	// exist, but we absolutely don't want that behaviour here.
	var fileInfo os.FileInfo
	var err error

	envFilePath := manager.GetEnvironmentFilePath()
	if fileInfo, err = os.Stat(envFilePath); err != nil && os.IsNotExist(err) {
		logger.Err(err).
			Str("path", envFilePath).
			Msg("iRODS environment file does not exist")
		return nil, err
	}
	if fileInfo.IsDir() {
		err = errors.New("iRODS environment file is a directory")
		logger.Err(err).
			Str("path", envFilePath).
			Msg("iRODS environment file is a directory")
		return nil, err
	}

	if err = manager.Load(os.Getpid()); err != nil {
		logger.Err(err).Msg("iRODS environment manager failed to load an environment")
		return nil, err
	}

	logger.Info().
		Str("path", envFilePath).
		Msg("Loaded iRODS environment file")

	var account *types.IRODSAccount
	if account, err = manager.ToIRODSAccount(); err != nil {
		logger.Err(err).Msg("Failed to obtain an iRODS account instance")
		return nil, err
	}

	logger.Info().
		Str("host", account.Host).
		Int("port", account.Port).
		Str("zone", account.ClientZone).
		Str("user", account.ClientUser).
		Str("auth_scheme", string(account.AuthenticationScheme)).
		Bool("cs_neg_required", account.ClientServerNegotiation).
		Str("cs_neg_policy", string(account.CSNegotiationPolicy)).
		Str("ca_cert_path", account.SSLConfiguration.CACertificatePath).
		Str("ca_cert_file", account.SSLConfiguration.CACertificateFile).
		Str("enc_alg", account.SSLConfiguration.EncryptionAlgorithm).
		Int("key_size", account.SSLConfiguration.EncryptionKeySize).
		Int("salt_size", account.SSLConfiguration.SaltSize).
		Int("hash_rounds", account.SSLConfiguration.HashRounds).
		Msg("iRODS account created")

	return account, nil
}

// isPublicReadable checks if the data object at the given path is readable by the
// public user of the zone hosting the file.
//
// If iRODS is federated, there may be multiple zones, each with their own public user.
// The zone argument is the zone of public user whose read permission is to be checked,
// which is normally the current zone. This is consulted only if the ACL user zone is
// empty.
func isPublicReadable(logger zerolog.Logger, filesystem *fs.FileSystem,
	userZone string, rodsPath string) (bool, error) {
	var acl []*types.IRODSAccess
	var pathZone string
	var err error

	if acl, err = filesystem.ListACLs(rodsPath); err != nil {
		return false, err
	}
	if pathZone, err = util.GetIRODSZone(rodsPath); err != nil {
		return false, err
	}

	for _, ac := range acl {
		// ACL user zone may be empty if it refers to the local zone
		var effectiveUserZone string
		if ac.UserZone != "" {
			effectiveUserZone = ac.UserZone
		} else {
			effectiveUserZone = userZone
		}

		if effectiveUserZone == pathZone &&
			ac.UserName == PublicUser &&
			ac.AccessLevel == types.IRODSAccessLevelReadObject {
			logger.Trace().
				Str("path", rodsPath).
				Msg("Public read access found")

			return true, nil
		}
	}

	logger.Trace().Str("path", rodsPath).Msg("Public read access not found")

	return false, nil
}

func getFileRange(logger zerolog.Logger, w http.ResponseWriter, r *http.Request,
	account *types.IRODSAccount, rodsPath string) {

	// TODO: filesystem is thread safe, so it can be shared across requests
	filesystem, err := fs.NewFileSystemWithDefault(account, AppName)
	if err != nil {
		logger.Err(err).Msg("Failed to create an iRODS file system")
		writeErrorResponse(logger, w, http.StatusInternalServerError)
		return
	}

	defer filesystem.Release()

	// Don't use filesystem.ExistsFile(objPath) here because it will return false if the
	// file _does_ exist on the iRODS server, but the server is down or unreachable.
	//
	// filesystem.StatFile(objPath) is better because we can check for the error type.
	_, err = filesystem.StatFile(rodsPath)
	if err != nil {
		if types.IsAuthError(err) {
			logger.Err(err).
				Str("path", rodsPath).
				Msg("Failed to authenticate with iRODS")
			writeErrorResponse(logger, w, http.StatusUnauthorized)
			return
		}
		if types.IsFileNotFoundError(err) {
			logger.Info().
				Str("path", rodsPath).
				Msg("Requested path does not exist")
			writeErrorResponse(logger, w, http.StatusNotFound)
			return
		}
		logger.Err(err).Str("path", rodsPath).Msg("Failed to stat file")
		writeErrorResponse(logger, w, http.StatusInternalServerError)
		return
	}

	zone := account.ClientZone
	publicReadable, err := isPublicReadable(logger, filesystem, zone, rodsPath)
	if err != nil {
		logger.Err(err).
			Str("path", rodsPath).
			Msg("Failed to check public read access")
		writeErrorResponse(logger, w, http.StatusInternalServerError)
		return
	}

	if !publicReadable {
		logger.Info().
			Str("path", rodsPath).
			Msg("Requested path is not public readable")
		writeErrorResponse(logger, w, http.StatusForbidden)
		return
	}

	fh, err := filesystem.OpenFile(rodsPath, "", "r")
	if err != nil {
		logger.Err(err).
			Str("path", rodsPath).
			Msg("Failed to open file")
		writeErrorResponse(logger, w, http.StatusInternalServerError)
		return
	}

	defer func(fh *fs.FileHandle) {
		if ferr := fh.Close(); ferr != nil {
			logger.Err(ferr).
				Str("path", rodsPath).
				Msg("Failed to close file handle")
		}
	}(fh)

	logger.Info().Str("path", rodsPath).Msg("Serving file")
	http.ServeContent(w, r, rodsPath, time.Now(), fh)
}
