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
	"path/filepath"
	"time"

	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/icommands"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/go-irodsclient/irods/util"
	"github.com/rs/zerolog"
)

const (
	IRODSEnvFileDefault = "~/.irods/irods_environment.json"
	IRODSEnvFileEnvVar  = "IRODS_ENVIRONMENT_FILE"
	IRODSPasswordEnvVar = "IRODS_PASSWORD"
	IRODSPublicUser     = "public"
)

const (
	Namespace          = "sqyrrl"
	NamespaceSeparator = ":"
	IndexAttr          = Namespace + NamespaceSeparator + "index"
	IndexValue         = "1"
	CategoryAttr       = Namespace + NamespaceSeparator + "category"
)

// IRODSEnvFilePath returns the path to the iRODS environment file. If the path
// is not set in the environment, the default path is returned.
func IRODSEnvFilePath() string {
	path := os.Getenv(IRODSEnvFileEnvVar)
	if path == "" {
		path = IRODSEnvFileDefault
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
func InitIRODS(logger zerolog.Logger, authFilePath string, password string) error {
	logger.Info().
		Str("path", authFilePath).
		Msg("Writing an iRODS auth file")
	return icommands.EncodePasswordFile(authFilePath, password, os.Getuid())
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
	manager *icommands.ICommandsEnvironmentManager) (account *types.IRODSAccount, err error) { // NRV
	// manager.Load() below will succeed even if the iRODS environment file does not
	// exist, but we absolutely don't want that behaviour here.

	envFilePath := manager.GetEnvironmentFilePath()

	var fileInfo os.FileInfo
	if fileInfo, err = os.Stat(envFilePath); err != nil && os.IsNotExist(err) {
		logger.Err(err).
			Str("path", envFilePath).
			Msg("iRODS environment file does not exist")
		return nil, err
	}
	if fileInfo.IsDir() {
		err = fmt.Errorf("iRODS environment file is a directory: %w", ErrInvalidArgument)
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

	if account, err = manager.ToIRODSAccount(); err != nil {
		logger.Err(err).Msg("Failed to obtain an iRODS account instance")
		return nil, err
	}

	authFilePath := manager.GetPasswordFilePath()
	if _, err = os.Stat(authFilePath); err != nil && errors.Is(err, os.ErrNotExist) {
		logger.Info().
			Str("path", authFilePath).
			Msg("iRODS auth file does not exist; using the iRODS password environment variable")

		password, ok := os.LookupEnv(IRODSPasswordEnvVar)
		if !ok {
			logger.Error().
				Str("variable", IRODSPasswordEnvVar).
				Msg("Environment variable not set")
			return nil, fmt.Errorf("%s environment variable was not set: %w",
				IRODSPasswordEnvVar, ErrMissingArgument)
		}
		if password == "" {
			logger.Error().
				Str("variable", IRODSPasswordEnvVar).
				Msg("Environment variable empty")
			return nil, fmt.Errorf("%s environment variable was empty: %w",
				IRODSPasswordEnvVar, ErrInvalidArgument)
		}
		account.Password = password

		if err = InitIRODS(logger, authFilePath, password); err != nil {
			logger.Err(err).
				Str("path", authFilePath).
				Msg("Failed to initialise iRODS")
			return nil, err
		}
	}

	logger.Info().
		Str("host", account.Host).
		Int("port", account.Port).
		Str("zone", account.ClientZone).
		Str("user", account.ClientUser).
		Str("env_file", manager.GetEnvironmentFilePath()).
		Str("auth_file", manager.GetPasswordFilePath()).
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

	// Before returning the account, check that it is usable by connecting to the
	// iRODS server and accessing the root collection.
	var filesystem *fs.FileSystem
	filesystem, err = fs.NewFileSystemWithDefault(account, AppName)
	if err != nil {
		logger.Err(err).Msg("Failed to create an iRODS file system")
		return nil, err
	}

	var root *fs.Entry
	root, err = filesystem.StatDir("/")
	if err != nil {
		logger.Err(err).Msg("Failed to stat the root zone collection")
		return nil, err
	}
	logger.Debug().
		Str("path", root.Path).
		Msg("Root zone collection is accessible")

	return account, err
}

// isPublicReadable checks if the data object at the given path is readable by the
// public user of the zone hosting the file.
//
// If iRODS is federated, there may be multiple zones, each with their own public user.
// The zone argument is the zone of public user whose read permission is to be checked,
// which is normally the current zone. This is consulted only if the ACL user zone is
// empty.
func isPublicReadable(logger zerolog.Logger, filesystem *fs.FileSystem,
	userZone string, rodsPath string) (_ bool, err error) {
	var acl []*types.IRODSAccess
	var pathZone string

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
			ac.UserName == IRODSPublicUser &&
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

// getFileRange serves a file from iRODS to the client. It delegates to http.ServeContent
// which sets the appropriate headers, including Content-Type.
func getFileRange(logger zerolog.Logger, w http.ResponseWriter, r *http.Request,
	account *types.IRODSAccount, rodsPath string) {

	// TODO: filesystem is thread safe, so it can be shared across requests
	var rodsFs *fs.FileSystem
	var err error
	if rodsFs, err = fs.NewFileSystemWithDefault(account, AppName); err != nil {
		logger.Err(err).Msg("Failed to create an iRODS file system")
		writeErrorResponse(logger, w, http.StatusInternalServerError)
		return
	}

	defer rodsFs.Release()

	// Don't use filesystem.ExistsFile(objPath) here because it will return false if the
	// file _does_ exist on the iRODS server, but the server is down or unreachable.
	//
	// filesystem.StatFile(objPath) is better because we can check for the error type.
	if _, err = rodsFs.StatFile(rodsPath); err != nil {
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

	var publicReadable bool
	if publicReadable, err = isPublicReadable(logger, rodsFs, zone, rodsPath); err != nil {
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

	var fh *fs.FileHandle
	if fh, err = rodsFs.OpenFile(rodsPath, "", "r"); err != nil {
		logger.Err(err).
			Str("path", rodsPath).
			Msg("Failed to open file")
		writeErrorResponse(logger, w, http.StatusInternalServerError)
		return
	}

	defer func(fh *fs.FileHandle) {
		if err = fh.Close(); err != nil {
			logger.Err(err).
				Str("path", rodsPath).
				Msg("Failed to close file handle")
		}
	}(fh)

	logger.Info().Str("path", rodsPath).Msg("Serving file")
	http.ServeContent(w, r, rodsPath, time.Now(), fh)
}

// The index attribute and value should be configurable so that individual users can
// customise the metadata used to index their data. This will allow them to focus on
// specific data objects or collections interesting to them.

// findItems runs a metadata query against iRODS to find any items that have metadata
// with the key sqyrrl::index and value 1. The items are grouped by the value of the
// metadata.
func findItems(filesystem *fs.FileSystem) (items []Item, err error) { // NRV
	filesystem.ClearCache() // Clears all caches (entries, metadata, ACLs)

	var entries []*fs.Entry
	if entries, err = filesystem.SearchByMeta(IndexAttr, IndexValue); err != nil {
		return nil, err
	}

	for _, entry := range entries {
		var acl []*types.IRODSAccess
		if acl, err = filesystem.ListACLs(entry.Path); err != nil {
			return nil, err
		}

		var metadata []*types.IRODSMeta
		if metadata, err = filesystem.ListMetadata(entry.Path); err != nil {
			return nil, err
		}

		items = append(items, Item{
			Path:     entry.Path,
			Size:     entry.Size,
			ACL:      acl,
			Metadata: metadata,
		})
	}
	return items, nil
}
