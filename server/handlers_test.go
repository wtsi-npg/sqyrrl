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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"time"

	"github.com/cyverse/go-irodsclient/irods/connection"
	ifs "github.com/cyverse/go-irodsclient/irods/fs"
	"github.com/cyverse/go-irodsclient/irods/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

var _ = Describe("iRODS Get Handler", func() {
	var specTimeout = time.Second * 5
	var workColl string
	var testFile, localPath, remotePath string

	BeforeEach(func(ctx SpecContext) {
		// Put a test file into iRODS
		workColl = TmpRodsPath(rootColl, "iRODSGetHandler")
		err := irodsFS.MakeDir(workColl, true)
		Expect(err).NotTo(HaveOccurred())

		testFile = "test.txt"
		localPath = filepath.Join("testdata", testFile)
		remotePath = path.Join(workColl, testFile)

		_, err = irodsFS.UploadFile(localPath, remotePath, "", false, true, true, nil)
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(time.Second*5))

	AfterEach(func() {
		// Remove the test file from iRODS
		err := irodsFS.RemoveFile(remotePath, true)
		Expect(err).NotTo(HaveOccurred())

		err = irodsFS.RemoveDir(workColl, true, true)
		Expect(err).NotTo(HaveOccurred())
	})

	When("a non-existent path is given", func() {
		var r *http.Request
		var handler http.Handler
		var err error

		BeforeEach(func(ctx SpecContext) {
			handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
			Expect(err).NotTo(HaveOccurred())

			objPath := path.Join(workColl, "no", "such", "file.txt")
			getURL, err := url.JoinPath(server.EndpointIRODS, objPath)
			Expect(err).NotTo(HaveOccurred())

			r, err = http.NewRequest("GET", getURL, nil)
			Expect(err).NotTo(HaveOccurred())
		}, NodeTimeout(time.Second*2))

		It("should return NotFound", func(ctx SpecContext) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)

			Expect(rec.Code).To(Equal(http.StatusNotFound))
		}, SpecTimeout(specTimeout))
	})

	When("a valid data object path is given", func() {
		When("the Sqyrrl user is not authenticated", func() {
			When("a valid data object path is given", func() {
				var r *http.Request
				var handler http.Handler
				var err error

				BeforeEach(func(ctx SpecContext) {
					handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
					Expect(err).NotTo(HaveOccurred())

					objPath := path.Join(workColl, testFile)
					getURL, err := url.JoinPath(server.EndpointIRODS, objPath)
					Expect(err).NotTo(HaveOccurred())

					r, err = http.NewRequest("GET", getURL, nil)
					Expect(err).NotTo(HaveOccurred())
				}, NodeTimeout(time.Second*2))

				When("the data object does not have read permissions for the public group", func() {
					It("should return Forbidden", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusForbidden))
					}, SpecTimeout(specTimeout))
				})

				When("the data object has read permissions for the public group", func() {
					var conn *connection.IRODSConnection

					BeforeEach(func(ctx SpecContext) {
						handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
						Expect(err).NotTo(HaveOccurred())

						conn, err = irodsFS.GetIOConnection()
						Expect(err).NotTo(HaveOccurred())

						err = ifs.ChangeDataObjectAccess(conn, remotePath, types.IRODSAccessLevelReadObject,
							server.IRODSPublicGroup, testZone, false)
						Expect(err).NotTo(HaveOccurred())
					}, NodeTimeout(time.Second*5))

					AfterEach(func() {
						err := irodsFS.ReturnIOConnection(conn)
						Expect(err).NotTo(HaveOccurred())
					})

					It("should return OK", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusOK))
					}, SpecTimeout(specTimeout))

					It("should serve the correct body content", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusOK))
						Expect(rec.Body.String()).To(Equal("test\n"))
					}, SpecTimeout(specTimeout))
				})
			})
		})

		When("the Sqyrrl user is authenticated", func() {
			var r *http.Request
			var handler http.Handler
			var err error

			var accessToken = "test_access_token"
			var sessionToken = "test_session_token"

			BeforeEach(func(ctx SpecContext) {
				handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
				Expect(err).NotTo(HaveOccurred())

				objPath := path.Join(workColl, testFile)
				getURL, err := url.JoinPath(server.EndpointIRODS, objPath)
				Expect(err).NotTo(HaveOccurred())

				r, err = http.NewRequest("GET", getURL, nil)
				Expect(err).NotTo(HaveOccurred())
			})

			When("the user is not in the public group", func() {
				BeforeEach(func(ctx SpecContext) {
					// Populate a session as if the user has authenticated through OIDC

					var c context.Context
					// There is no session for this token, so a new session will always be created
					c, err = sessManager.Load(r.Context(), sessionToken)
					sessManager.Put(c, server.SessionKeyAccessToken, accessToken)
					sessManager.Put(c, server.SessionKeyUserName, userNotInPublic)
					sessManager.Put(c, server.SessionKeyUserEmail, userNotInPublic+"@sanger.ac.uk")
					r = r.WithContext(c)

					// A real session token is created here, but we don't need it
					_, _, err = sessManager.Commit(r.Context())
					Expect(err).NotTo(HaveOccurred())
				}, NodeTimeout(time.Second*2))

				When("the data object does not have read permissions for the public group", func() {
					It("should return Forbidden", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusForbidden))
					}, SpecTimeout(specTimeout))

					When("the data object has read permissions for another of the user's groups", func() {
						var conn *connection.IRODSConnection

						BeforeEach(func(ctx SpecContext) {
							handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
							Expect(err).NotTo(HaveOccurred())

							conn, err = irodsFS.GetIOConnection()
							Expect(err).NotTo(HaveOccurred())

							err = ifs.ChangeDataObjectAccess(conn, remotePath, types.IRODSAccessLevelReadObject,
								populatedGroup, testZone, false)
							Expect(err).NotTo(HaveOccurred())
						}, NodeTimeout(time.Second*5))

						AfterEach(func() {
							err := irodsFS.ReturnIOConnection(conn)
							Expect(err).NotTo(HaveOccurred())
						})

						It("should return OK", func(ctx SpecContext) {
							rec := httptest.NewRecorder()
							handler.ServeHTTP(rec, r)

							Expect(rec.Code).To(Equal(http.StatusOK))
						}, SpecTimeout(specTimeout))
					})
				})

				When("the data object has read permissions for the public group", func() {
					var conn *connection.IRODSConnection

					BeforeEach(func(ctx SpecContext) {
						handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
						Expect(err).NotTo(HaveOccurred())

						conn, err = irodsFS.GetIOConnection()
						Expect(err).NotTo(HaveOccurred())

						err = ifs.ChangeDataObjectAccess(conn, remotePath, types.IRODSAccessLevelReadObject,
							server.IRODSPublicGroup, testZone, false)
						Expect(err).NotTo(HaveOccurred())
					}, NodeTimeout(time.Second*5))

					AfterEach(func() {
						err := irodsFS.ReturnIOConnection(conn)
						Expect(err).NotTo(HaveOccurred())
					})

					It("should return Ok", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusOK))
					}, SpecTimeout(specTimeout))
				})
			})

			When("the user is in the public group", func() {
				BeforeEach(func(ctx SpecContext) {
					// Populate a session as if the user has authenticated through OIDC

					var c context.Context
					// There is no session for this token, so a new session will always be created
					c, err = sessManager.Load(r.Context(), sessionToken)
					sessManager.Put(c, server.SessionKeyAccessToken, accessToken)
					sessManager.Put(c, server.SessionKeyUserName, userInPublic)
					sessManager.Put(c, server.SessionKeyUserEmail, userInPublic+"@sanger.ac.uk")
					r = r.WithContext(c)

					// A real session token is created here, but we don't need it
					_, _, err = sessManager.Commit(r.Context())
					Expect(err).NotTo(HaveOccurred())
				}, NodeTimeout(time.Second*2))

				When("the data object does not have read permissions for the public group", func() {
					It("should return Forbidden", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusForbidden))
					}, SpecTimeout(specTimeout))
				})

				When("the data object has read permissions for the public group", func() {
					var conn *connection.IRODSConnection

					BeforeEach(func(ctx SpecContext) {
						handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
						Expect(err).NotTo(HaveOccurred())

						conn, err = irodsFS.GetIOConnection()
						Expect(err).NotTo(HaveOccurred())

						err = ifs.ChangeDataObjectAccess(conn, remotePath, types.IRODSAccessLevelReadObject,
							server.IRODSPublicGroup, testZone, false)
						Expect(err).NotTo(HaveOccurred())
					}, NodeTimeout(time.Second*5))

					AfterEach(func() {
						err := irodsFS.ReturnIOConnection(conn)
						Expect(err).NotTo(HaveOccurred())
					})

					It("should return OK", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusOK))
					}, SpecTimeout(specTimeout))

					It("should serve the correct body content", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusOK))
						Expect(rec.Body.String()).To(Equal("test\n"))
					}, SpecTimeout(specTimeout))

				})
			})
		})
	})
})
