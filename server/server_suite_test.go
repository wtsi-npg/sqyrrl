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

package server_test

import (
	"errors"
	"fmt"
	"github.com/alexedwards/scs/v2"
	"github.com/cyverse/go-irodsclient/config"
	"github.com/cyverse/go-irodsclient/irods/connection"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cyverse/go-irodsclient/fs"
	ifs "github.com/cyverse/go-irodsclient/irods/fs"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/rs/zerolog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

var (
	suiteName   = "Sqyrrl Server Test Suite"
	suiteLogger zerolog.Logger

	account *types.IRODSAccount
	irodsFS *fs.FileSystem

	iRODSEnvFilePath  = "testdata/config/test_irods_environment.json"
	iRODSAuthFilePath = "testdata/config/test_auth_file"
	iRODSPassword     = "irods"

	testZone = "testZone"
	rootColl = fmt.Sprintf("/%s/home/irods", testZone)

	emptyGroup     = "empty_group#testZone"
	populatedGroup = "populated_group#testZone"

	userInPublic    = "user_in_public#testZone"
	userNotInPublic = "user_not_in_public#testZone"

	// This is to test cases where a user is a member of multiple groups
	otherGroups = []string{
		"group_1#testZone",
		"group_2#testZone",
		"group_3#testZone",
		"group_4#testZone",
		"group_5#testZone",
	}
	userInOthers = "user_in_others#testZone"

	sqyrrlConfig server.Config
	sessManager  *scs.SessionManager
	sqyrrlServer *server.SqyrrlServer
)

func TestSuite(t *testing.T) {
	writer := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	suiteLogger = zerolog.New(writer).With().Timestamp().Logger().Level(zerolog.TraceLevel)

	RegisterFailHandler(Fail)
	RunSpecs(t, suiteName)
}

// Set up the iRODS environment and create a new iRODS filesystem
var _ = BeforeSuite(func(ctx SpecContext) {
	var err error

	err = os.Setenv(server.IRODSEnvFileEnvVar, iRODSEnvFilePath)
	Expect(err).NotTo(HaveOccurred())

	// Ensure that tests start without an auth file present
	err = os.Remove(iRODSAuthFilePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		Expect(err).NotTo(HaveOccurred())
	}

	// Set up iRODS account
	var manager *config.ICommandsEnvironmentManager
	manager, err = server.NewICommandsEnvironmentManager(suiteLogger, iRODSEnvFilePath)
	Expect(err).NotTo(HaveOccurred())

	err = server.InitIRODS(suiteLogger, manager, iRODSPassword)
	Expect(err).NotTo(HaveOccurred())

	var iRODSEnvFilePathAbs string
	iRODSEnvFilePathAbs, err = filepath.Abs(iRODSEnvFilePath)
	Expect(err).NotTo(HaveOccurred())
	Expect(manager.EnvironmentFilePath).To(Equal(iRODSEnvFilePathAbs))
	Expect(manager.Environment.Password).To(Equal(iRODSPassword))

	account, err = server.NewIRODSAccount(suiteLogger, manager, iRODSPassword)
	Expect(err).NotTo(HaveOccurred())

	irodsFS, err = fs.NewFileSystemWithDefault(account, suiteName)
	Expect(err).NotTo(HaveOccurred())

	// Add iRODS users
	var suiteConn *connection.IRODSConnection
	suiteConn, err = irodsFS.GetIOConnection()
	Expect(err).NotTo(HaveOccurred())

	defer func(irodsFS *fs.FileSystem, conn *connection.IRODSConnection) {
		err := irodsFS.ReturnIOConnection(conn)
		if err != nil {
			suiteLogger.Error().Err(err).Msg("Failed to return iRODS connection cleanly")
		}
	}(irodsFS, suiteConn)

	testUsers := []string{userInPublic, userNotInPublic, userInOthers}
	currentUsers := make(map[string]struct{})

	var users []*types.IRODSUser
	users, err = ifs.ListUsers(suiteConn)
	Expect(err).NotTo(HaveOccurred())

	for _, u := range users {
		currentUsers[u.Name] = struct{}{}
	}

	for _, userName := range testUsers {
		user := server.ParseUser(userName)
		if _, ok := currentUsers[user.Name]; !ok {
			err = ifs.CreateUser(suiteConn, user.Name, user.Zone, string(types.IRODSUserRodsUser))
			Expect(err).NotTo(HaveOccurred())
		}
	}

	testGroups := slices.Concat([]string{emptyGroup, populatedGroup}, otherGroups)
	currentGroups := make(map[string]struct{})

	var groups []*types.IRODSUser
	groups, err = ifs.ListGroups(suiteConn)
	Expect(err).NotTo(HaveOccurred())

	for _, group := range groups {
		currentGroups[group.Name] = struct{}{}
	}

	for _, groupName := range testGroups {
		group := server.ParseUser(groupName)
		if _, ok := currentGroups[group.Name]; !ok {
			err = ifs.CreateGroup(suiteConn, group.Name, string(types.IRODSUserRodsGroup))
			Expect(err).NotTo(HaveOccurred())
		}
	}

	// None of the following group membership operations clear the go-irodsclient cache
	// so calls via FileSystem will still return the old data. There doesn't appear to
	// be a way to clear the user/group membership cache, so we work around this by
	// replacing the irodsFS object with a new one.

	setGroupMembership := func(conn *connection.IRODSConnection, userName, groupName string, isMember bool) {
		user := server.ParseUser(userName)
		group := server.ParseUser(groupName)
		inGroup, err := server.UserInGroup(suiteLogger, irodsFS, user, group)
		Expect(err).NotTo(HaveOccurred())

		if inGroup != isMember {
			if isMember {
				suiteLogger.Info().Msgf("Adding user %s to group %s", user.Name, group.Name)
				err = ifs.AddGroupMember(conn, group.Name, user.Name, testZone)
			} else {
				suiteLogger.Info().Msgf("Removing user %s from group %s", user.Name, group.Name)
				err = ifs.RemoveGroupMember(conn, group.Name, user.Name, testZone)
			}
			Expect(err).NotTo(HaveOccurred())
		}
	}

	setGroupMembership(suiteConn, userInPublic, server.IRODSPublicGroup, true)
	setGroupMembership(suiteConn, userNotInPublic, server.IRODSPublicGroup, false)
	setGroupMembership(suiteConn, userNotInPublic, populatedGroup, true)
	for _, group := range otherGroups {
		setGroupMembership(suiteConn, userInOthers, group, true)
	}

	// Replace irodsFS with a new instance to clear the cache
	irodsFS.Release()
	irodsFS, err = fs.NewFileSystemWithDefault(account, suiteName)
	Expect(err).NotTo(HaveOccurred())

	checkGroupMembership := func(fs *fs.FileSystem, userName, groupName string, shouldBeMember bool) {
		user := server.ParseUser(userName)
		group := server.ParseUser(groupName)
		inGroup, err := server.UserInGroup(suiteLogger, fs, user, group)
		Expect(err).NotTo(HaveOccurred())
		Expect(inGroup).To(Equal(shouldBeMember))
	}

	// Check group membership
	checkGroupMembership(irodsFS, userInPublic, server.IRODSPublicGroup, true)
	checkGroupMembership(irodsFS, userNotInPublic, server.IRODSPublicGroup, false)
	checkGroupMembership(irodsFS, userNotInPublic, populatedGroup, true)
	for _, group := range otherGroups {
		checkGroupMembership(irodsFS, userInOthers, group, true)
	}

	// OIDC is not enabled for testing. We test for authenticated cases by creating
	// a session manager and populating it with a session that simulates OIDC
	// authentication.
	sqyrrlConfig = server.Config{
		Host:          "127.0.0.1",
		Port:          "9999",
		CertFilePath:  "./testdata/config/localhost.crt",
		KeyFilePath:   "./testdata/config/localhost.key",
		IndexInterval: time.Hour * 1,
		EnableOIDC:    false,
	}
	sessManager = scs.New()

	err = server.Configure(suiteLogger, &sqyrrlConfig)
	Expect(err).NotTo(HaveOccurred())

	sqyrrlServer, err = server.NewSqyrrlServer(suiteLogger, &sqyrrlConfig, sessManager)
	Expect(err).NotTo(HaveOccurred())

	// server could be started here if testing with network connections
	// err = sqyrrlServer.StartBackground()
	// Expect(err).NotTo(HaveOccurred())
}, NodeTimeout(time.Second*20))

// Release the iRODS filesystem
var _ = AfterSuite(func() {
	sqyrrlServer.Stop()
	irodsFS.Release()

	// Clean up any auth file that may have been created
	err := os.Remove(iRODSAuthFilePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		Expect(err).NotTo(HaveOccurred())
	}
})

// Return a new pseudo-randomised path in iRODS
func TmpRodsPath(root string, prefix string) string {
	s := rand.NewSource(GinkgoRandomSeed())
	r := rand.New(s)
	d := fmt.Sprintf("%s.%d.%010d", prefix, os.Getpid(), r.Uint32())
	return filepath.Join(root, d)
}
