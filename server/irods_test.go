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
	"github.com/cyverse/go-irodsclient/irods/connection"
	"path"
	"path/filepath"
	"time"

	ifs "github.com/cyverse/go-irodsclient/irods/fs"
	"github.com/cyverse/go-irodsclient/irods/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

var _ = Describe("iRODS functions", func() {
	var conn *connection.IRODSConnection
	var zone string
	var workColl string
	var testFile, localPath, remotePath string
	var err error

	BeforeEach(func(ctx SpecContext) {
		zone = "testZone"
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
		It("should return a FileNotFoundError", func() {
			_, err := server.IsReadableByUser(suiteLogger, irodsFS, userInPublic,
				zone, "/no/such/path")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(&types.FileNotFoundError{}))
		})
	})

	When("a non-existent user is given", func() {
		It("should return false", func() {
			readable, err := server.IsReadableByUser(suiteLogger, irodsFS, "no_such_user",
				zone, remotePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(readable).To(BeFalse())
		})
	})

	When("a valid data object path is given", func() {
		When("the data object has no permissions for the public group", func() {
			BeforeEach(func(ctx SpecContext) {
				err = ifs.ChangeDataObjectAccess(conn, remotePath,
					types.IRODSAccessLevelNull, server.IRODSPublicGroup, testZone, false)
				Expect(err).NotTo(HaveOccurred())
			})

			When("the user is in the public group", func() {
				It("should return false", func() {
					readable, err := server.IsReadableByUser(suiteLogger, irodsFS, userInPublic,
						zone, remotePath)
					Expect(err).NotTo(HaveOccurred())
					Expect(readable).To(BeFalse())
				})
			})

			When("the user is not in the public group", func() {
				It("should return false", func() {
					readable, err := server.IsReadableByUser(suiteLogger, irodsFS, userNotInPublic,
						zone, remotePath)
					Expect(err).NotTo(HaveOccurred())
					Expect(readable).To(BeFalse())
				})
			})
		})

		When("the data object has read permissions for the public group", func() {
			BeforeEach(func(ctx SpecContext) {
				err = ifs.ChangeDataObjectAccess(conn, remotePath,
					types.IRODSAccessLevelReadObject, server.IRODSPublicGroup, testZone, false)
				Expect(err).NotTo(HaveOccurred())
			})

			When("the user is in the public group", func() {
				It("should return true", func() {
					readable, err := server.IsReadableByUser(suiteLogger, irodsFS, userInPublic,
						zone, remotePath)
					Expect(err).NotTo(HaveOccurred())
					Expect(readable).To(BeTrue())
				})
			})

			When("the user is not in the public group", func() {
				It("should return false", func() {
					readable, err := server.IsReadableByUser(suiteLogger, irodsFS, userNotInPublic,
						zone, remotePath)
					Expect(err).NotTo(HaveOccurred())
					Expect(readable).To(BeFalse())
				})
			})
		})

		When("the data object has own permissions for the public group", func() {
			BeforeEach(func(ctx SpecContext) {
				err = ifs.ChangeDataObjectAccess(conn, remotePath,
					types.IRODSAccessLevelOwner, server.IRODSPublicGroup, testZone, false)
				Expect(err).NotTo(HaveOccurred())
			})

			When("the user is in the public group", func() {
				It("should return true", func() {
					readable, err := server.IsReadableByUser(suiteLogger, irodsFS, userInPublic,
						zone, remotePath)
					Expect(err).NotTo(HaveOccurred())
					Expect(readable).To(BeTrue())
				})
			})

			When("the user is not in the public group", func() {
				It("should return false", func() {
					readable, err := server.IsReadableByUser(suiteLogger, irodsFS, userNotInPublic,
						zone, remotePath)
					Expect(err).NotTo(HaveOccurred())
					Expect(readable).To(BeFalse())
				})
			})
		})
	})
})
