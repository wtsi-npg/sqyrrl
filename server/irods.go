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

// LookupIRODSEnvFilePath returns the path to the iRODS environment file set in the
// environment. If not set, the default path is returned.
func LookupIRODSEnvFilePath() string {
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
func InitIRODS(logger zerolog.Logger, manager *icommands.ICommandsEnvironmentManager) (err error) {
	authFilePath := manager.GetPasswordFilePath()
	if _, err = os.Stat(authFilePath); err != nil && os.IsNotExist(err) {
		logger.Info().
			Str("path", authFilePath).
			Msg("No iRODS auth file present; writing one now")
		return icommands.EncodePasswordFile(authFilePath, manager.Password, os.Getuid())
	}
	return err
}

// NewICommandsEnvironmentManager creates a new environment iRODSEnvManager instance.
//
// This function creates a iRODSEnvManager and sets the iRODS environment file path from the
// shell environment. If an iRODS auth file is present, the password is read from it.
// Otherwise, the password is read from the shell environment.
func NewICommandsEnvironmentManager(logger zerolog.Logger,
	iRODSEnvFilePath string) (manager *icommands.ICommandsEnvironmentManager, err error) {
	if iRODSEnvFilePath == "" {
		return nil, fmt.Errorf("iRODS environment file path was empty: %w",
			ErrInvalidArgument)
	}

	// iRODSEnvManager.Load() below will succeed even if the iRODS environment file does not
	// exist, but we absolutely don't want that behaviour here.
	var fileInfo os.FileInfo
	if fileInfo, err = os.Stat(iRODSEnvFilePath); err != nil && os.IsNotExist(err) {
		return nil, err
	}
	if fileInfo.IsDir() {
		return nil, fmt.Errorf("iRODS environment file is a directory: %w",
			ErrInvalidArgument)
	}
	if manager, err = icommands.CreateIcommandsEnvironmentManager(); err != nil {
		return nil, err
	}
	if err = manager.SetEnvironmentFilePath(iRODSEnvFilePath); err != nil {
		return nil, err
	}
	if err = manager.Load(os.Getpid()); err != nil {
		return nil, err
	}

	logger.Info().
		Str("path", iRODSEnvFilePath).
		Msg("Loaded iRODS environment file")

	authFilePath := manager.GetPasswordFilePath()

	// An existing auth file takes precedence over the environment variable
	if _, err = os.Stat(authFilePath); err != nil && os.IsNotExist(err) {
		password, ok := os.LookupEnv(IRODSPasswordEnvVar)
		if !ok {
			return nil, fmt.Errorf("iRODS auth file '%s' was not present "+
				"and the '%s' environment variable needed to create it was not set: %w",
				authFilePath, IRODSPasswordEnvVar, ErrMissingArgument)
		}
		if password == "" {
			return nil, fmt.Errorf("iRODS auth file '%s' was not present "+
				"and the '%s' environment variable needed to set it was empty: %w",
				authFilePath, IRODSPasswordEnvVar, ErrInvalidArgument)
		}

		manager.Password = password // The password is propagated to the iRODS account
	}

	return manager, nil
}

// NewIRODSAccount returns an iRODS account instance using the iRODS environment for
// configuration. The environment file path is obtained from the iRODS environment
// manager.
func NewIRODSAccount(logger zerolog.Logger,
	manager *icommands.ICommandsEnvironmentManager) (account *types.IRODSAccount, err error) { // NRV
	if account, err = manager.ToIRODSAccount(); err != nil {
		logger.Err(err).Msg("Failed to obtain an iRODS account instance")
		return nil, err
	}

	if err = InitIRODS(logger, manager); err != nil {
		logger.Err(err).
			Str("path", manager.GetPasswordFilePath()).
			Msg("Failed to initialise iRODS")
		return nil, err
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
