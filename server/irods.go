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
	"slices"
	"strings"
	"time"

	"github.com/cyverse/go-irodsclient/config"
	ifs "github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/go-irodsclient/irods/util"
	"github.com/rs/zerolog"
)

const (
	IRODSEnvFileDefault = "~/.irods/irods_environment.json"
	IRODSEnvFileEnvVar  = "IRODS_ENVIRONMENT_FILE"

	IRODSPublicGroup = "public"
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
func InitIRODS(logger zerolog.Logger, manager *config.ICommandsEnvironmentManager,
	password string) (err error) {
	if password == "" {
		return fmt.Errorf("password was empty: %w", ErrInvalidArgument)
	}

	obfuscator := config.NewPasswordObfuscator()
	obfuscator.SetUID(manager.UID)

	manager.Environment.Password = password
	authFilePath := manager.PasswordFilePath
	if _, err = os.Stat(authFilePath); err != nil && os.IsNotExist(err) {
		logger.Info().
			Str("path", authFilePath).
			Msg("No iRODS auth file present; writing one now")
		return obfuscator.EncodeToFile(authFilePath, []byte(password))
	}
	return err
}

// NewICommandsEnvironmentManager creates a new environment iRODSEnvManager instance.
//
// This function creates a iRODSEnvManager and sets the iRODS environment file path from the
// shell environment. If an iRODS auth file is present, the password is read from it.
// Otherwise, the password is read from the shell environment.
func NewICommandsEnvironmentManager(logger zerolog.Logger,
	iRODSEnvFilePath string) (manager *config.ICommandsEnvironmentManager, err error) {
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
	if manager, err = config.NewICommandsEnvironmentManager(); err != nil {
		return nil, err
	}
	if err = manager.SetEnvironmentFilePath(iRODSEnvFilePath); err != nil {
		return nil, err
	}

	if err = manager.Load(); err != nil {
		return nil, err
	}

	logger.Info().
		Str("path", iRODSEnvFilePath).
		Msg("Loaded iRODS environment file")

	return manager, nil
}

// NewIRODSAccount returns an iRODS account instance using the iRODS environment for
// configuration. The environment file path is obtained from the iRODS environment
// manager. If the iRODS password is an empty string, it is assumed that the iRODS
// auth file is already present.
func NewIRODSAccount(logger zerolog.Logger, manager *config.ICommandsEnvironmentManager,
	password string) (account *types.IRODSAccount, err error) { // NRV
	if account, err = manager.ToIRODSAccount(); err != nil {
		logger.Err(err).Msg("Failed to obtain an iRODS account instance")
		return nil, err
	}

	if password != "" {
		if err = InitIRODS(logger, manager, password); err != nil {
			logger.Err(err).
				Str("path", manager.PasswordFilePath).
				Msg("Failed to initialise iRODS")
			return nil, err
		}
	}

	logger.Info().
		Str("host", account.Host).
		Int("port", account.Port).
		Str("zone", account.ClientZone).
		Str("user", account.ClientUser).
		Str("env_file", manager.EnvironmentFilePath).
		Str("auth_file", manager.PasswordFilePath).
		Bool("password", password != "").
		Str("auth_scheme", string(account.AuthenticationScheme)).
		Bool("cs_neg_required", account.ClientServerNegotiation).
		Str("cs_neg_policy", string(account.CSNegotiationPolicy)).
		Str("ca_cert_path", account.SSLConfiguration.CACertificatePath).
		Str("ca_cert_file", account.SSLConfiguration.CACertificateFile).
		Str("enc_alg", account.SSLConfiguration.EncryptionAlgorithm).
		Int("key_size", account.SSLConfiguration.EncryptionKeySize).
		Msg("iRODS account created")

	// Before returning the account, check that it is usable by connecting to the
	// iRODS server and accessing the root collection.
	var filesystem *ifs.FileSystem
	filesystem, err = ifs.NewFileSystemWithDefault(account, AppName)
	if err != nil {
		logger.Err(err).Msg("Failed to create an iRODS file system")
		return nil, err
	}

	var root *ifs.Entry
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

// IsReadableByUser checks if the data object at the given path is readable by the
// given user in the zone hosting the file.
//
// If iRODS is federated, there may be multiple zones, each with their own users.
// The zone argument is the zone of user whose read permission is to be checked,
// which is normally the current zone. This is consulted only if the ACL user zone is
// empty.
//
// A file is considered readable if the user has read access or is in a group that has
// read access.
func IsReadableByUser(logger zerolog.Logger, filesystem *ifs.FileSystem,
	userName string, userZone string, rodsPath string) (_ bool, err error) {
	var acl []*types.IRODSAccess
	var pathZone string

	if acl, err = filesystem.ListACLs(rodsPath); err != nil {
		return false, err
	}
	if pathZone, err = util.GetIRODSZone(rodsPath); err != nil {
		return false, err
	}

	var userGroups []*types.IRODSUser
	userGroups, err = filesystem.ListUserGroups(userName)
	if err != nil {
		return false, err
	}

	groupNames := make([]string, 0, len(userGroups))
	userGroupLookup := make(map[string]struct{}, len(userGroups))
	for _, group := range userGroups {
		groupNames = append(groupNames, group.Name)
		userGroupLookup[group.Name] = struct{}{}
	}
	slices.Sort(groupNames)

	logger.Trace().
		Str("path", rodsPath).
		Str("user", userName).
		Str("zone", userZone).
		Int("num_groups", len(userGroups)).
		Str("groups", fmt.Sprintf("[%v]", strings.Join(groupNames, ", "))).
		Msg("Checking read access")

	for _, ac := range acl {
		// ACL user zone may be empty if it refers to the local zone
		var effectiveUserZone string
		if ac.UserZone != "" {
			effectiveUserZone = ac.UserZone
		} else {
			effectiveUserZone = userZone
		}

		hasRead := ac.AccessLevel == types.IRODSAccessLevelReadObject
		hasOwn := ac.AccessLevel == types.IRODSAccessLevelOwner

		// There is permission directly for the user
		if ac.UserType == types.IRODSUserRodsUser || ac.UserType == types.IRODSUserRodsAdmin {
			if effectiveUserZone == pathZone && ac.UserName == userName && (hasRead || hasOwn) {
				logger.Trace().
					Str("path", rodsPath).
					Str("user", userName).
					Str("zone", userZone).
					Str("effective_zone", effectiveUserZone).
					Str("ac_user", ac.UserName).
					Str("ac_level", string(ac.AccessLevel)).
					Bool("read", hasRead).
					Bool("own", hasOwn).
					Msg("User access found")

				return true, nil
			}

			logger.Trace().
				Str("path", rodsPath).
				Str("user", userName).
				Str("zone", userZone).
				Str("ac_user", ac.UserName).
				Str("effective_zone", effectiveUserZone).
				Str("path_zone", pathZone).
				Str("ac_level", string(ac.AccessLevel)).
				Bool("read", hasRead).
				Bool("own", hasOwn).
				Msg("User read access not found")
		}

		// There is permission for a group the user is in
		if ac.UserType == types.IRODSUserRodsGroup {
			// Check if user in the group of this AC (ac.UserName is the name of the AC's group, unfortunately)
			_, userInGroup := userGroupLookup[ac.UserName]

			if effectiveUserZone == pathZone && userInGroup && (hasRead || hasOwn) {
				logger.Trace().
					Str("path", rodsPath).
					Str("user", userName).
					Str("zone", userZone).
					Str("effective_zone", effectiveUserZone).
					Str("ac_user", ac.UserName).
					Str("ac_level", string(ac.AccessLevel)).
					Bool("read", hasRead).
					Bool("own", hasOwn).
					Bool("user_in_group", userInGroup).
					Msg("Group access found")

				return true, nil
			}
		}
	}

	logger.Trace().
		Str("path", rodsPath).
		Str("user", userName).
		Str("zone", userZone).
		Msg("No access found")

	return false, nil
}

func UserInGroup(logger zerolog.Logger, filesystem *ifs.FileSystem,
	userName string, userZone string, groupName string) (_ bool, err error) {
	var groups []*types.IRODSUser
	if groups, err = filesystem.ListUserGroups(userName); err != nil {
		return false, err
	}

	for _, group := range groups {
		logger.Trace().
			Str("user", userName).
			Str("zone", userZone).
			Str("group", group.Name).
			Msg("Checking user group")

		if group.Zone == "" {
			return group.Name == groupName, nil
		}

		return group.Zone == userZone && group.Name == groupName, nil
	}

	return false, nil
}

func IsPublicReadable(logger zerolog.Logger, filesystem *ifs.FileSystem,
	userZone string, rodsPath string) (_ bool, err error) {
	var acl []*types.IRODSAccess
	if acl, err = filesystem.ListACLs(rodsPath); err != nil {
		return false, err
	}

	for _, ac := range acl {
		if ac.UserName == IRODSPublicGroup &&
			ac.UserZone == userZone &&
			(ac.AccessLevel == types.IRODSAccessLevelReadObject ||
				ac.AccessLevel == types.IRODSAccessLevelOwner) {
			logger.Trace().
				Str("path", rodsPath).
				Str("user", IRODSPublicGroup).
				Msg("Public read access found")

			return true, nil
		}
	}

	logger.Trace().Str("path", rodsPath).Msg("No public read access found")
	return false, nil
}

// getFileRange serves a file from iRODS to the client. It delegates to http.ServeContent
// which sets the appropriate headers, including Content-Type.
func getFileRange(logger zerolog.Logger, w http.ResponseWriter, r *http.Request,
	rodsFs *ifs.FileSystem, rodsPath string) {
	var err error

	var fh *ifs.FileHandle
	if fh, err = rodsFs.OpenFile(rodsPath, "", "r"); err != nil {
		logger.Err(err).
			Str("path", rodsPath).
			Msg("Failed to open file")
		writeErrorResponse(logger, w, http.StatusInternalServerError)
		return
	}

	defer func(fh *ifs.FileHandle) {
		if err := fh.Close(); err != nil {
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
func findItems(filesystem *ifs.FileSystem) (items []Item, err error) { // NRV
	filesystem.ClearCache() // Clears all caches (entries, metadata, ACLs)

	var entries []*ifs.Entry
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
