/*
 * Copyright (C) 2024, 2025. Genome Research Ltd. All rights reserved.
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
	"strings"
	"time"

	"github.com/cyverse/go-irodsclient/config"
	ifs "github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/rs/zerolog"
)

func ParseUser(name string) types.IRODSUser {
	n, z, _ := strings.Cut(name, "#")
	return types.IRODSUser{Name: n, Zone: z}
}

// Authoriser is an interface for a subset of the ifs.FileSystem methods, which means
// that the latter implements the former. This is useful for testing, where a mock
// implementation of Authoriser can be used.
type Authoriser interface {
	// ListUsers returns a list of all iRODS users.
	ListUsers() ([]*types.IRODSUser, error)

	// ListGroupUsers returns a list of all users in the given iRODS group.
	ListGroupUsers(group string) ([]*types.IRODSUser, error)

	// ListACLs returns an iRODS access control list for the given path.
	ListACLs(path string) ([]*types.IRODSAccess, error)

	// Stat returns the metadata for the given path. Authorisation is not checked.
	// Authoriser implements this to allow its other methods to return FileNotFoundErrors
	// appropriately.
	Stat(path string) (*ifs.Entry, error)
}

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
// given user in the zone the Sqyrrl server is logged into.
//
// If iRODS is federated, there may be multiple zones, each with their own users.
//
// The localZone argument is the zone that Sqyrrl is logged into. This is consulted
// only if an access permission in the data object's ACL has an empty user zone, in which
// case the local zone is assumed.
//
// The userZone argument is the zone of the user whose read permission is to be checked.
//
// A file is considered readable if the user has read access or is in a group that has
// read access.
func IsReadableByUser(logger zerolog.Logger, authoriser Authoriser,
	localZone string, user types.IRODSUser, rodsPath string) (_ bool, err error) {
	var acl []*types.IRODSAccess
	var users []*types.IRODSUser

	localUserExists := false
	if users, err = authoriser.ListUsers(); err != nil {
		return false, err
	}

	for _, u := range users {
		if u.Name == user.Name && u.Zone == user.Zone {
			localUserExists = true
			break
		}
	}

	subLogger := logger.With().
		Str("local_zone", localZone).
		Str("path", rodsPath).
		Str("user", user.Name).
		Str("zone", user.Zone).Logger()

	if _, err = authoriser.Stat(rodsPath); err != nil {
		return false, err
	}

	if !localUserExists {
		subLogger.Warn().Msg("Expected local iRODS user does not exist")
		return false, nil
	}

	// ACL user zone may be empty if it refers to the local zone
	if acl, err = authoriser.ListACLs(rodsPath); err != nil {
		return false, err
	}
	for _, ac := range acl {
		if ac.UserZone == "" {
			ac.UserZone = localZone
		}
	}

	subLogger.Trace().
		Int("num_acls_for_path", len(acl)).
		Msg("Checking read access")

	for _, ac := range acl {
		hasRead := ac.AccessLevel == types.IRODSAccessLevelReadObject
		hasOwn := ac.AccessLevel == types.IRODSAccessLevelOwner

		aclLogger := subLogger.With().
			Str("ac_user", ac.UserName).
			Str("ac_zone", ac.UserZone).
			Str("ac_level", string(ac.AccessLevel)).
			Bool("read", hasRead).
			Bool("own", hasOwn).Logger()

		switch ac.UserType {
		// There is permission directly for the user
		case types.IRODSUserRodsUser, types.IRODSUserRodsAdmin, types.IRODSUserGroupAdmin:
			if ac.UserName == user.Name && ac.UserZone == user.Zone && (hasRead || hasOwn) {
				aclLogger.Trace().Msg(fmt.Sprintf("User access granted"))
				return true, nil
			}

		// There is permission for a group the user is in
		case types.IRODSUserRodsGroup:
			// ac.UserName is the name of the AC's group, unfortunately

			// note a "ac.UserZone == user.Zone" check would be wrong here as:
			// - ac.UserZone is for the group whilst user.Zone is for the user (in the group)
			// - groups (assumed to be) only for the zone being served - no federation of groups
			// - equivalent zone check is done in the group membership logic
			if ac.UserZone != localZone {
				aclLogger.Warn().
					Msg("Unexpected group zone in this permission; expected the group " +
						"zone to equal the local zone")
				continue
			}

			var userInGroup bool
			group := types.IRODSUser{Name: ac.UserName, Zone: ac.UserZone}
			if userInGroup, err = UserInGroup(logger, authoriser, user, group); err != nil {
				return false, err
			}

			if userInGroup && (hasRead || hasOwn) {
				aclLogger.Trace().Msg("Group access granted")
				return true, nil
			}

		default:
			return false, errors.New("ACL user type not accounted for")
		}
	}

	subLogger.Trace().Msg("Access not granted")

	return false, nil
}

func UserInGroup(logger zerolog.Logger, authoriser Authoriser,
	user types.IRODSUser, group types.IRODSUser) (_ bool, err error) {
	var groupMembers []*types.IRODSUser
	if groupMembers, err = authoriser.ListGroupUsers(group.Name); err != nil {
		return false, err
	}

	groupLogger := logger.With().Str("user", user.Name).
		Str("zone", user.Zone).
		Str("group", group.Name).
		Str("group_zone", group.Zone).Logger()

	for _, member := range groupMembers {
		if user.Name == member.Name && user.Zone == member.Zone {
			groupLogger.Trace().Msg("User is in group")
			return true, nil
		}
	}
	groupLogger.Trace().Msg("User is not in group")

	return false, nil
}

func IsPublicReadable(logger zerolog.Logger, authoriser Authoriser, rodsPath string) (_ bool, err error) {
	var acl []*types.IRODSAccess
	if acl, err = authoriser.ListACLs(rodsPath); err != nil {
		return false, err
	}

	for _, ac := range acl {
		if ac.UserName == IRODSPublicGroup &&
			ac.UserType == types.IRODSUserRodsGroup &&
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
