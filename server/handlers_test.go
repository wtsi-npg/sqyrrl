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
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"

	"github.com/cyverse/go-irodsclient/irods/connection"
	"github.com/cyverse/go-irodsclient/irods/fs"
	"github.com/cyverse/go-irodsclient/irods/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

var _ = Describe("iRODS Get Handler", func() {
	var testZone, rootColl, workColl string
	var testFile, localPath, remotePath string

	BeforeEach(func() {
		// Put a test file into iRODS
		testZone = "testZone"
		rootColl = fmt.Sprintf("/%s/home/irods", testZone)
		workColl = TmpRodsPath(rootColl, "iRODSGetHandler")

		err := irodsFS.MakeDir(workColl, true)
		Expect(err).NotTo(HaveOccurred())

		testFile = "test.txt"
		localPath = filepath.Join("testdata", testFile)
		remotePath = path.Join(workColl, testFile)

		err = irodsFS.UploadFile(localPath, remotePath, "", false, nil)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		// Remove the test file from iRODS
		err := irodsFS.RemoveDir(workColl, true, true)
		Expect(err).NotTo(HaveOccurred())
	})

	When("a non-existent path is given", func() {
		var r *http.Request
		var err error

		BeforeEach(func() {
			url := fmt.Sprintf("/get?%s=/no/such/file.txt", server.HTTPParamPath)
			r, err = http.NewRequest("GET", url, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return NotFound", func() {
			handler := server.HandleIRODSGet(suiteLogger, account)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)

			Expect(rec.Code).To(Equal(http.StatusNotFound))
		})
	})

	When("a valid data object path is given", func() {
		var r *http.Request
		var err error

		BeforeEach(func() {
			path := path.Join(workColl, testFile)
			url := fmt.Sprintf("/get?%s=%s", server.HTTPParamPath, path)
			r, err = http.NewRequest("GET", url, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		When("the data object file does not have public read permissions", func() {
			It("should return Forbidden", func() {
				handler := server.HandleIRODSGet(suiteLogger, account)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, r)

				Expect(rec.Code).To(Equal(http.StatusForbidden))
			})
		})

		When("the data object does have public read permissions", func() {
			var conn *connection.IRODSConnection
			var acl []*types.IRODSAccess
			var err error

			BeforeEach(func() {
				conn, err = irodsFS.GetIOConnection()
				Expect(err).NotTo(HaveOccurred())

				err = fs.ChangeDataObjectAccess(conn, remotePath, types.IRODSAccessLevelReadObject,
					server.PublicUser, testZone, false)
				Expect(err).NotTo(HaveOccurred())

				acl, err = irodsFS.ListFileACLsWithGroupUsers(remotePath)
				Expect(err).NotTo(HaveOccurred())

				var publicAccess bool
				for _, ac := range acl {
					suiteLogger.Info().
						Str("user", ac.UserName).
						Str("expected_user", server.PublicUser).
						Str("zone", ac.UserZone).
						Str("expected_zone", testZone).
						Str("access", ac.AccessLevel.ChmodString()).
						Str("expected_access", types.IRODSAccessLevelReadObject.ChmodString()).
						Msg("ACL")

					if ac.UserName == server.PublicUser &&
						ac.UserZone == testZone &&
						server.LevelsEqual(ac.AccessLevel, types.IRODSAccessLevelReadObject) {
						publicAccess = true
					}
				}
				Expect(publicAccess).To(BeTrue())
			})

			AfterEach(func() {
				irodsFS.ReturnIOConnection(conn)
			})

			It("should return OK", func() {
				handler := server.HandleIRODSGet(suiteLogger, account)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, r)

				Expect(rec.Code).To(Equal(http.StatusOK))
			})

			It("should serve the correct body content", func() {
				handler := server.HandleIRODSGet(suiteLogger, account)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, r)

				Expect(rec.Code).To(Equal(http.StatusOK))
				Expect(rec.Body.String()).To(Equal("test\n"))
			})
		})
	})
})
