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
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"time"

	"github.com/cyverse/go-irodsclient/irods/connection"
	ifs "github.com/cyverse/go-irodsclient/irods/fs"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/oauth2-proxy/mockoidc"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

var _ = Describe("iRODS Get Handler", func() {
	var specTimeout = time.Second * 5
	var workColl string
	var localPath, remotePath string
	var getURL string

	BeforeEach(func(ctx SpecContext) {
		// Put a test file into iRODS
		workColl = TmpRodsPath(rootColl, "iRODSGetHandler")
		err := irodsFS.MakeDir(workColl, true)
		Expect(err).NotTo(HaveOccurred())

		testFile := "test.txt"
		localPath = filepath.Join("testdata", testFile)
		remotePath = path.Join(workColl, testFile)

		objPath := path.Join(workColl, testFile)
		getURL, err = url.JoinPath(server.EndpointIRODS, objPath)
		Expect(err).NotTo(HaveOccurred())

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

		BeforeEach(func(ctx SpecContext) {
			var err error
			handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
			Expect(err).NotTo(HaveOccurred())

			objPath := path.Join(workColl, "no", "such", "file.txt")
			nonExistentURL, err := url.JoinPath(server.EndpointIRODS, objPath)
			Expect(err).NotTo(HaveOccurred())

			r, err = http.NewRequest("GET", nonExistentURL, nil)
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

				BeforeEach(func(ctx SpecContext) {
					var err error
					handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
					Expect(err).NotTo(HaveOccurred())

					r, err = http.NewRequest("GET", getURL, nil)
					Expect(err).NotTo(HaveOccurred())
				}, NodeTimeout(time.Second*2))

				When("the data object does not have read permissions for the public group", func() {
					It("should return a redirect to the auth server", func(ctx SpecContext) {
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, r)

						Expect(rec.Code).To(Equal(http.StatusFound))
						Expect(rec.Header().Get("Location")).To(ContainSubstring(mockoidcServer.AuthorizationEndpoint()))
					}, SpecTimeout(specTimeout))
				})

				When("the data object has read permissions for the public group", func() {
					var conn *connection.IRODSConnection

					BeforeEach(func(ctx SpecContext) {
						var err error
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
			var handler http.Handler
			var r *http.Request

			var accessToken = "test_access_token"
			var sessionToken = "test_session_token"

			BeforeEach(func(ctx SpecContext) {
				var err error
				handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
				Expect(err).NotTo(HaveOccurred())

				r, err = http.NewRequest("GET", getURL, nil)
				Expect(err).NotTo(HaveOccurred())
			})

			When("the user is not in the public group", func() {
				BeforeEach(func(ctx SpecContext) {
					// Populate a session as if the user has authenticated through OIDC

					// There is no session for this token, so a new session will always be created
					c, err := sessManager.Load(r.Context(), sessionToken)

					user := server.ParseUser(userNotInPublic)
					sessManager.Put(c, server.SessionKeyAccessToken, accessToken)
					sessManager.Put(c, server.SessionKeyUserName, user.Name)
					sessManager.Put(c, server.SessionKeyUserEmail, user.Name+"@sanger.ac.uk")
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
							var err error
							handler, err = sqyrrlServer.GetHandler(server.EndpointIRODS)
							Expect(err).NotTo(HaveOccurred())

							conn, err = irodsFS.GetIOConnection()
							Expect(err).NotTo(HaveOccurred())

							group := server.ParseUser(populatedGroup)
							err = ifs.ChangeDataObjectAccess(conn, remotePath, types.IRODSAccessLevelReadObject,
								group.Name, group.Zone, false)
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
						var err error
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
				})
			})

			When("the user is in the public group", func() {
				BeforeEach(func(ctx SpecContext) {
					// Populate a session as if the user has authenticated through OIDC

					// There is no session for this token, so a new session will always be created
					c, err := sessManager.Load(r.Context(), sessionToken)

					user := server.ParseUser(userInPublic)
					sessManager.Put(c, server.SessionKeyAccessToken, accessToken)
					sessManager.Put(c, server.SessionKeyUserName, user.Name)
					sessManager.Put(c, server.SessionKeyUserEmail, user.Name+"@sanger.ac.uk")
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
						var err error
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

// NewCookieEnabledHTTPClient returns a configured http.Client with cookie support and
// optional redirect handling. The client is configured with:
//
// - A cookie jar for cookie management
// - An insecure transport that skips TLS certificate verification
// - Optional redirect handling controlled by the redirect parameter
//
// Parameters:
//   - redirect: if false, the client will not follow redirects and return the redirect response instead.
//
// Returns:
//   - *http.Client: configured HTTP client instance
func NewCookieEnabledHTTPClient(redirect bool) *http.Client {
	jar, err := cookiejar.New(nil)
	Expect(err).NotTo(HaveOccurred())

	insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	httpClient := &http.Client{
		Transport: insecureTransport,
		Jar:       jar,
	}
	if !redirect {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// special case to stop the redirect chain
			return http.ErrUseLastResponse
		}
	}
	return httpClient
}

var _ = Describe("Authentication Handler", func() {
	When("Logging in to Sqyrrl", func() {
		var ws *http.Response
		var err error

		httpClient := NewCookieEnabledHTTPClient(false)

		It("should return a 302 redirect to OIDC server", func(ctx SpecContext) {
			url := url.URL{
				Scheme: "https",
				Host:   net.JoinHostPort(sqyrrlConfig.Host, sqyrrlConfig.Port),
				Path:   server.EndpointLogin,
			}
			ws, err = httpClient.Post(url.String(), "application/x-www-form-urlencoded", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(ws.StatusCode).To(Equal(http.StatusFound))
			Expect(ws.Header.Get("Location")).To(ContainSubstring(mockoidcServer.AuthorizationEndpoint()))
		}, NodeTimeout(time.Second*2))

		When("contacting the OIDC server", func() {
			var wo *http.Response

			BeforeEach(func(ctx SpecContext) {
				mockoidcServer.UserQueue.Push(&mockoidc.MockUser{
					Email: "someuser@somewhere.com",
				})
			})

			AfterEach(func(ctx SpecContext) {
				mockoidcServer.UserQueue.Pop()
			})

			It("should return a 302 redirect to the Sqyrrl auth callback", func(ctx SpecContext) {
				wo, err = httpClient.Get(ws.Header.Get("Location"))
				Expect(err).NotTo(HaveOccurred())
				Expect(wo.StatusCode).To(Equal(http.StatusFound))
				Expect(wo.Header.Get("Location")).To(ContainSubstring(server.EndpointAuthCallback))
			}, NodeTimeout(time.Second*2))

			When("calling the Sqyrrl auth callback", func() {
				var wscb *http.Response

				It("should return a 302 redirect to the home page", func(ctx SpecContext) {
					wscb, err = httpClient.Get(wo.Header.Get("Location"))
					Expect(err).NotTo(HaveOccurred())
					Expect(wscb.StatusCode).To(Equal(http.StatusFound))
					Expect(wscb.Header.Get("Location")).To(Equal(server.EndpointRoot)) // can do exact check as redirect is relative
				}, NodeTimeout(time.Second*2))

				When("following the redirect to the home page", func() {
					It("should return a 200 OK and show the user's email", func(ctx SpecContext) {
						var wsh *http.Response
						url := url.URL{
							Scheme: "https",
							Host:   net.JoinHostPort(sqyrrlConfig.Host, sqyrrlConfig.Port),
							Path:   wscb.Header.Get("Location"),
						}
						// need to form url from relative path
						wsh, err = httpClient.Get(url.String())
						Expect(err).NotTo(HaveOccurred())
						Expect(wsh.StatusCode).To(Equal(http.StatusOK))

						var bodyBytes []byte
						bodyBytes, err = io.ReadAll(wsh.Body)
						Expect(err).NotTo(HaveOccurred())
						Expect(string(bodyBytes)).To(ContainSubstring("someuser@somewhere.com"))
					}, NodeTimeout(time.Second*2))
				})
			})
		})
	})

})

var _ = Describe("Seamless Auth Flow", func() {
	var localPath, remotePath string
	var workColl string

	BeforeEach(func(ctx SpecContext) {
		// Put a test file into iRODS
		workColl = TmpRodsPath(rootColl, "iRODSGetHandler")
		err := irodsFS.MakeDir(workColl, true)
		Expect(err).NotTo(HaveOccurred())

		testFile := "test.txt"
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

	When("Accessing a file marked with the public group", func() {
		var conn *connection.IRODSConnection

		BeforeEach(func(ctx SpecContext) {
			var err error
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

		It("should return a 200 OK and correct content", func(ctx SpecContext) {
			httpClient := NewCookieEnabledHTTPClient(true)
			getURL, err := url.JoinPath(server.EndpointIRODS, remotePath)
			Expect(err).NotTo(HaveOccurred())

			var wsh *http.Response
			url := url.URL{
				Scheme: "https",
				Host:   net.JoinHostPort(sqyrrlConfig.Host, sqyrrlConfig.Port),
				Path:   getURL,
			}
			wsh, err = httpClient.Get(url.String())
			Expect(err).NotTo(HaveOccurred())
			Expect(wsh.StatusCode).To(Equal(http.StatusOK))

			var bodyBytes []byte
			bodyBytes, err = io.ReadAll(wsh.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(bodyBytes)).To(Equal("test\n"))
		}, NodeTimeout(time.Second*2))
	})

	When("Accessing a file not marked with the public group", func() {
		var conn *connection.IRODSConnection

		BeforeEach(func(ctx SpecContext) {
			var err error
			conn, err = irodsFS.GetIOConnection()
			Expect(err).NotTo(HaveOccurred())

			err = ifs.ChangeDataObjectAccess(conn, remotePath, types.IRODSAccessLevelReadObject,
				server.ParseUser(populatedGroup).Name, testZone, false)
			Expect(err).NotTo(HaveOccurred())
		}, NodeTimeout(time.Second*5))

		AfterEach(func() {
			err := irodsFS.ReturnIOConnection(conn)
			Expect(err).NotTo(HaveOccurred())
		})

		When("not authenticated", func() {
			It("should return a 403 Forbidden", func(ctx SpecContext) {
				httpClient := NewCookieEnabledHTTPClient(true)
				getURL, err := url.JoinPath(server.EndpointIRODS, remotePath)
				Expect(err).NotTo(HaveOccurred())

				var wsh *http.Response
				url := url.URL{
					Scheme: "https",
					Host:   net.JoinHostPort(sqyrrlConfig.Host, sqyrrlConfig.Port),
					Path:   getURL,
				}
				wsh, err = httpClient.Get(url.String())
				Expect(err).NotTo(HaveOccurred())
				Expect(wsh.StatusCode).To(Equal(http.StatusForbidden))
			}, NodeTimeout(time.Second*2))
		})

		When("authenticated with user who has access", func() {
			BeforeEach(func(ctx SpecContext) {
				mockoidcServer.UserQueue.Push(&mockoidc.MockUser{
					Email: server.ParseUser(userNotInPublic).Name + "@whereever.com",
				})
			})

			AfterEach(func(ctx SpecContext) {
				mockoidcServer.UserQueue.Pop()
			})

			It("should return a 200 OK and correct content", func(ctx SpecContext) {
				httpClient := NewCookieEnabledHTTPClient(true)
				getURL, err := url.JoinPath(server.EndpointIRODS, remotePath)
				Expect(err).NotTo(HaveOccurred())

				var wsh *http.Response
				url := url.URL{
					Scheme: "https",
					Host:   net.JoinHostPort(sqyrrlConfig.Host, sqyrrlConfig.Port),
					Path:   getURL,
				}
				wsh, err = httpClient.Get(url.String())
				Expect(err).NotTo(HaveOccurred())
				Expect(wsh.StatusCode).To(Equal(http.StatusOK))

				var bodyBytes []byte
				bodyBytes, err = io.ReadAll(wsh.Body)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(bodyBytes)).To(Equal("test\n"))
			}, NodeTimeout(time.Second*2))
		})

		When("authenticated with user who does not have access", func() {
			BeforeEach(func(ctx SpecContext) {
				mockoidcServer.UserQueue.Push(&mockoidc.MockUser{
					Email: server.ParseUser(userInOthers).Name + "@whereever.com",
				})
			})

			AfterEach(func(ctx SpecContext) {
				mockoidcServer.UserQueue.Pop()
			})

			It("should return a 403 forbidden", func(ctx SpecContext) {
				httpClient := NewCookieEnabledHTTPClient(true)
				getURL, err := url.JoinPath(server.EndpointIRODS, remotePath)
				Expect(err).NotTo(HaveOccurred())

				var wsh *http.Response
				url := url.URL{
					Scheme: "https",
					Host:   net.JoinHostPort(sqyrrlConfig.Host, sqyrrlConfig.Port),
					Path:   getURL,
				}
				wsh, err = httpClient.Get(url.String())
				Expect(err).NotTo(HaveOccurred())
				Expect(wsh.StatusCode).To(Equal(http.StatusForbidden))

				var bodyBytes []byte
				bodyBytes, err = io.ReadAll(wsh.Body)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(bodyBytes)).To(Not(ContainSubstring("test")))
			}, NodeTimeout(time.Second*2))
		})
	})
})
