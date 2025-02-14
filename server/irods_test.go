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

package server_test

import (
	"github.com/cyverse/go-irodsclient/irods/connection"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/cyverse/go-irodsclient/fs"
	ifs "github.com/cyverse/go-irodsclient/irods/fs"
	"github.com/cyverse/go-irodsclient/irods/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

type mockAuthoriser struct {
	users      map[string]*types.IRODSUser // Map of user names to user objects
	groups     map[string]*types.IRODSUser // Map of group names to group objects
	membership map[string][]string         // Map of group names to user names
	aclGroups  []string                    // List of group names that have read access to all mock paths
	paths      map[string]struct{}         // Lookup table of mock paths that exist
	zone       string                      // The iRODS zone, applied to unqualified user and group names
}

// newMockAuthoriser creates a new mockAuthoriser with the given user names, group
// names and zones. The membership map is a map of group names to user names that
// describes the membership of each group.
//
// The ACL returned for any path will show it to be readable by all groups.
func newMockAuthoriser(userNames, groupNames []string, membership map[string][]string,
	aclGroups []string) *mockAuthoriser {
	authoriser := &mockAuthoriser{
		users:      make(map[string]*types.IRODSUser),
		groups:     make(map[string]*types.IRODSUser),
		membership: make(map[string][]string),
		aclGroups:  aclGroups,
		paths:      make(map[string]struct{}),
		zone:       testZone,
	}

	ensureZone := func(name string) (n string, z string) {
		n, z, _ = strings.Cut(name, "#")
		if z == "" {
			z = authoriser.zone
		}
		return
	}

	addEntity := func(name, zone string,
		entityType types.IRODSUserType,
		entityMap map[string]*types.IRODSUser) {
		key := name + "#" + zone
		entityMap[key] = &types.IRODSUser{Name: name, Zone: zone, Type: entityType}
	}

	for _, userName := range userNames {
		name, zone := ensureZone(userName)
		addEntity(name, zone, types.IRODSUserRodsUser, authoriser.users)
	}

	for _, groupName := range groupNames {
		name, zone := ensureZone(groupName)
		addEntity(name, zone, types.IRODSUserRodsGroup, authoriser.groups)
	}

	for groupName, memberNames := range membership {
		gName, gZone := ensureZone(groupName)

		var users []string
		for _, userName := range memberNames {
			uName, uZone := ensureZone(userName)
			users = append(users, uName+"#"+uZone)
		}

		key := gName + "#" + gZone
		authoriser.membership[key] = users
	}

	return authoriser
}

// ListUsers returns a list of all users in the mock authoriser. It never returns an error.
func (m *mockAuthoriser) ListUsers() ([]*types.IRODSUser, error) {
	var users []*types.IRODSUser
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

// ListGroupUsers returns a list of all users in the given group. It never returns an error.
func (m *mockAuthoriser) ListGroupUsers(group string) ([]*types.IRODSUser, error) {
	var groupUsers []*types.IRODSUser

	// Handle unqualified group names
	if !strings.Contains(group, "#") {
		group = group + "#" + m.zone
	}

	if userNames, ok := m.membership[group]; ok {
		for _, userName := range userNames {
			if user, ok := m.users[userName]; ok {
				groupUsers = append(groupUsers, user)
			}
		}
	}
	return groupUsers, nil
}

// ListACLs returns a list of all ACLs for the given path. If the path does not exist,
// it returns a FileNotFoundError, otherwise it does not return an error.
func (m *mockAuthoriser) ListACLs(path string) ([]*types.IRODSAccess, error) {
	if _, ok := m.paths[path]; !ok {
		return nil, &types.FileNotFoundError{}
	}

	var acl []*types.IRODSAccess
	for _, groupName := range m.aclGroups {
		if !strings.Contains(groupName, "#") {
			groupName = groupName + "#" + m.zone
		}

		group, ok := m.groups[groupName]
		if !ok {
			return nil, types.NewUserNotFoundError(groupName)
		}

		acl = append(acl, &types.IRODSAccess{
			Path:        path,
			UserName:    group.Name,
			UserZone:    group.Zone,
			UserType:    group.Type,
			AccessLevel: types.IRODSAccessLevelReadObject,
		})
	}
	return acl, nil
}

// Stat always returns an empty entry for the given path. If the path does not exist,
// in the mock authoriser, it returns a FileNotFoundError.
func (m *mockAuthoriser) Stat(path string) (*fs.Entry, error) {
	e := &fs.Entry{}
	if _, ok := m.paths[path]; !ok {
		return e, &types.FileNotFoundError{}
	}
	return e, nil
}

// addPath adds a path to the mock authoriser. After it is added, the authoriser will no
// longer return a FileNotFoundError for that path.
func (m *mockAuthoriser) addPath(path string) {
	m.paths[path] = struct{}{}
}

var _ = Describe("Mock authoriser", func() {
	// A demo (and test) of the mock authoriser
	var authoriser *mockAuthoriser

	BeforeEach(func() {
		// mockAuthoriser adds the default zone to unqualified user and group names
		users := []string{"user1", "user2", "user3"}
		groups := []string{"group1", "group2", "group3", "group4"}
		groupMembers := map[string][]string{
			"group1": {"user1"},
			"group2": {"user1"},
			"group3": {"user2", "user3"},
		}
		aclGroups := groups
		authoriser = newMockAuthoriser(users, groups, groupMembers, aclGroups)
	})

	When("a user is given", func() {
		It("should detect when the user is in a group", func() {
			var inGroup bool
			var err error

			for _, groupName := range []string{"group1#testZone", "group2#testZone"} {
				user := server.ParseUser("user1#testZone")
				group := server.ParseUser(groupName)
				inGroup, err = server.UserInGroup(suiteLogger, authoriser, user, group)
				Expect(err).NotTo(HaveOccurred())
				Expect(inGroup).To(BeTrue())
			}
			for _, userName := range []string{"user2#testZone", "user3#testZone"} {
				user := server.ParseUser(userName)
				group := server.ParseUser("group1#testZone")
				inGroup, err = server.UserInGroup(suiteLogger, authoriser, user, group)
				Expect(err).NotTo(HaveOccurred())
				Expect(inGroup).To(BeFalse())

				group = server.ParseUser("group3#testZone")
				inGroup, err = server.UserInGroup(suiteLogger, authoriser, user, group)
				Expect(err).NotTo(HaveOccurred())
				Expect(inGroup).To(BeTrue())
			}

			for _, userName := range []string{"user1#testZone", "user2#testZone", "user3#testZone"} {
				user := server.ParseUser(userName)
				group := server.ParseUser("group4#testZone")
				inGroup, err = server.UserInGroup(suiteLogger, authoriser, user, group)
				Expect(err).NotTo(HaveOccurred())
				Expect(inGroup).To(BeFalse())
			}
		})
	})

	When("aclGroups is populated", func() {
		It("should contain one AC per group", func() {
			authoriser.addPath("testPath")
			acls, err := authoriser.ListACLs("testPath")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(acls)).To(Equal(len(authoriser.aclGroups)))
		})
	})
})

var _ = Describe("iRODS functions", func() {
	var conn *connection.IRODSConnection
	var workColl string
	var testFile, localPath, remotePath string
	var err error

	var localZone = "testZone"     // This is a real zone on the test server
	var remoteZone = "anotherZone" // This represents a federated zone on another server

	BeforeEach(func(ctx SpecContext) {
		workColl = TmpRodsPath(rootColl, "iRODSGetHandler")
		err = irodsFS.MakeDir(workColl, true)
		Expect(err).NotTo(HaveOccurred())

		testFile = "test.txt"
		localPath = filepath.Join("testdata", testFile)
		remotePath = path.Join(workColl, testFile)

		_, err = irodsFS.UploadFile(localPath, remotePath, "", false, true, true, nil)
		Expect(err).NotTo(HaveOccurred())

		conn, err = irodsFS.GetIOConnection()
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(time.Second*5))

	AfterEach(func() {
		// Remove the test file from iRODS
		err := irodsFS.RemoveDir(workColl, true, true)
		Expect(err).NotTo(HaveOccurred())

		err = irodsFS.ReturnIOConnection(conn)
		Expect(err).NotTo(HaveOccurred())
	})

	When("a non-existent path is given", func() {
		It("should return a FileNotFoundError for a user in the local zone", func() {
			user := server.ParseUser(userInPublic)
			_, err := server.IsReadableByUser(suiteLogger, irodsFS, localZone, user, "/no/such/path")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(&types.FileNotFoundError{}))
		})

		It("should return a FileNotFoundError for a user in a remote zone", func() {
			mockAuth := newMockAuthoriser(
				[]string{userInPublic},
				[]string{server.IRODSPublicGroup},
				map[string][]string{server.IRODSPublicGroup: {userInPublic}},
				[]string{server.IRODSPublicGroup})

			user := server.ParseUser(userInPublic)
			_, err := server.IsReadableByUser(suiteLogger, mockAuth, localZone, user, "/no/such/path")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(&types.FileNotFoundError{}))
		})
	})

	When("a non-existent user is given", func() {
		It("should return false for a user in the local zone", func() {
			user := types.IRODSUser{Name: "no_such_user", Zone: testZone}
			readable, err := server.IsReadableByUser(suiteLogger, irodsFS, localZone, user, remotePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(readable).To(BeFalse())
		})

		It("should return false for a user in a remote zone", func() {
			mockAuth := newMockAuthoriser(
				[]string{userInPublic},
				[]string{server.IRODSPublicGroup},
				map[string][]string{server.IRODSPublicGroup: {userInPublic}},
				[]string{server.IRODSPublicGroup})
			mockAuth.addPath(remotePath)

			user := types.IRODSUser{Name: "no_such_user", Zone: remoteZone}
			readable, err := server.IsReadableByUser(suiteLogger, mockAuth, localZone, user, remotePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(readable).To(BeFalse())
		})
	})

	When("a user is given", func() {
		When("the user is in multiple groups", func() {
			It("should detect when the user is in a group", func() {
				user := server.ParseUser(userInOthers)

				for _, groupName := range otherGroups {
					group := server.ParseUser(groupName)
					inGroup, err := server.UserInGroup(suiteLogger, irodsFS, user, group)
					Expect(err).NotTo(HaveOccurred())
					Expect(inGroup).To(BeTrue())
				}
				group := server.ParseUser(emptyGroup)
				inGroup, err := server.UserInGroup(suiteLogger, irodsFS, user, group)
				Expect(err).NotTo(HaveOccurred())
				Expect(inGroup).To(BeFalse())
			})
		})
	})

	When("a valid data object path is given", func() {
		When("the user is in the local zone", func() {
			When("the data object has no permissions for the local public group", func() {
				BeforeEach(func(ctx SpecContext) {
					err = ifs.ChangeDataObjectAccess(conn, remotePath,
						types.IRODSAccessLevelNull, server.IRODSPublicGroup, localZone, false)
					Expect(err).NotTo(HaveOccurred())
				})

				When("the user is in the local public group", func() {
					It("should return false", func() {
						user := server.ParseUser(userInOthers)
						readable, err := server.IsReadableByUser(suiteLogger, irodsFS, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeFalse())
					})
				})

				When("the user is not in the local public group", func() {
					It("should return false", func() {
						user := server.ParseUser(userNotInPublic)
						readable, err := server.IsReadableByUser(suiteLogger, irodsFS, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeFalse())
					})
				})
			})
		})

		When("the user is in a remote zone", func() {
			When("the data object has no permissions for the local public group", func() {
				var mockAuth *mockAuthoriser

				When("the user is in the local public group", func() {
					BeforeEach(func(ctx SpecContext) {
						mockAuth = newMockAuthoriser(
							[]string{userInPublic},
							[]string{server.IRODSPublicGroup, "dummy_group"},
							map[string][]string{server.IRODSPublicGroup: {userInPublic}},
							[]string{"dummy_group"})
						mockAuth.addPath(remotePath)
					})

					It("should return false", func() {
						user := server.ParseUser(userInPublic)
						readable, err := server.IsReadableByUser(suiteLogger, mockAuth, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeFalse())
					})
				})

				When("the user is not in the local public group", func() {
					BeforeEach(func(ctx SpecContext) {
						mockAuth = newMockAuthoriser(
							[]string{userInPublic},
							[]string{server.IRODSPublicGroup, "dummy_group"},
							map[string][]string{server.IRODSPublicGroup: {}},
							[]string{"dummy_group"})
						mockAuth.addPath(remotePath)
					})

					It("should return false", func() {
						user := server.ParseUser(userNotInPublic)
						readable, err := server.IsReadableByUser(suiteLogger, mockAuth, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeFalse())
					})
				})
			})
		})

		When("the user is in the local zone", func() {
			When("the data object has read permissions for the local public group", func() {
				BeforeEach(func(ctx SpecContext) {
					err = ifs.ChangeDataObjectAccess(conn, remotePath,
						types.IRODSAccessLevelReadObject, server.IRODSPublicGroup, localZone, false)
					Expect(err).NotTo(HaveOccurred())
				})

				When("the user is in the local public group", func() {
					It("should return true", func() {
						user := server.ParseUser(userInPublic)
						readable, err := server.IsReadableByUser(suiteLogger, irodsFS, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeTrue())
					})
				})

				When("the user is not in the local public group", func() {
					It("should return false", func() {
						user := server.ParseUser(userNotInPublic)
						readable, err := server.IsReadableByUser(suiteLogger, irodsFS, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeFalse())
					})
				})
			})
		})

		When("the user is in a remote zone", func() {
			When("the data object has read permissions for the local public group", func() {
				var mockAuth *mockAuthoriser

				When("the user is in the local public group", func() {
					BeforeEach(func(ctx SpecContext) {
						mockAuth = newMockAuthoriser(
							[]string{userInPublic},
							[]string{server.IRODSPublicGroup},
							map[string][]string{server.IRODSPublicGroup: {userInPublic}},
							[]string{server.IRODSPublicGroup})
						mockAuth.addPath(remotePath)
					})

					It("should return false", func() {
						user := server.ParseUser(userInPublic)
						readable, err := server.IsReadableByUser(suiteLogger, mockAuth, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeTrue())
					})
				})

				When("the user is not in the local public group", func() {
					BeforeEach(func(ctx SpecContext) {
						mockAuth = newMockAuthoriser(
							[]string{userInPublic},
							[]string{server.IRODSPublicGroup},
							map[string][]string{server.IRODSPublicGroup: {}},
							[]string{server.IRODSPublicGroup})
						mockAuth.addPath(remotePath)
					})

					It("should return false", func() {
						user := server.ParseUser(userNotInPublic)
						readable, err := server.IsReadableByUser(suiteLogger, mockAuth, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeFalse())
					})
				})
			})
		})

		When("the data object has read permissions for several groups", func() {
			BeforeEach(func(ctx SpecContext) {
				for _, groupName := range otherGroups {
					group := server.ParseUser(groupName)
					err = ifs.ChangeDataObjectAccess(conn, remotePath,
						types.IRODSAccessLevelReadObject, group.Name, group.Zone, false)
					Expect(err).NotTo(HaveOccurred())
				}
			})

			When("the user is in one of the groups", func() {
				var mockAuth *mockAuthoriser

				It("should return true", func() {
					user := server.ParseUser(userInOthers)
					readable, err := server.IsReadableByUser(suiteLogger, irodsFS, localZone, user, remotePath)
					Expect(err).NotTo(HaveOccurred())
					Expect(readable).To(BeTrue())
				})

				When("the user is in a the "+remoteZone+" zone", func() {
					BeforeEach(func(ctx SpecContext) {
						mockAuth = newMockAuthoriser(
							[]string{userInPublic},
							[]string{server.IRODSPublicGroup},
							map[string][]string{server.IRODSPublicGroup: {userInPublic}},
							[]string{server.IRODSPublicGroup})
						mockAuth.addPath(remotePath)
					})

					It("should return false", func() {
						user := server.ParseUser(userInOthers)
						readable, err := server.IsReadableByUser(suiteLogger, mockAuth, localZone, user, remotePath)
						Expect(err).NotTo(HaveOccurred())
						Expect(readable).To(BeFalse())
					})
				})
			})

			When("the user is not in one of the groups", func() {
				It("should return false", func() {
					user := server.ParseUser(userNotInPublic)
					readable, err := server.IsReadableByUser(suiteLogger, irodsFS, localZone, user, remotePath)
					Expect(err).NotTo(HaveOccurred())
					Expect(readable).To(BeFalse())
				})
			})
		})
	})
})
