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
	"context"
	"crypto/rand"
	"encoding/base64"
	"io/fs"
	"net/http"
	"path"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/xid"
	"github.com/rs/zerolog/hlog"
)

// HandlerChain is a function that takes an http.Handler and returns a new http.Handler
// wrapping the input handler. Each handler in the chain should process the request in
// some way, and then call the next handler. Ideally, the functionality of each handler
// should be orthogonal to the others.
//
// This is sometimes called "middleware" in Go.
type HandlerChain func(http.Handler) http.Handler

// HandleHomePage is a handler for the static home page.
func HandleHomePage(server *SqyrrlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := server.logger
		logger.Trace().Msg("HomeHandler called")

		requestPath := r.URL.Path
		requestMethod := r.Method

		if requestPath != "/" && requestMethod == "GET" {
			redirect := path.Join(EndPointIRODS, requestPath)
			logger.Trace().
				Str("from", requestPath).
				Str("to", redirect).
				Str("method", requestMethod).
				Msg("Redirecting to API")
			http.Redirect(w, r, redirect, http.StatusPermanentRedirect)
		}

		type pageData struct {
			LoginURL         string
			LogoutURL        string
			AuthAvailable    bool
			Authenticated    bool
			UserName         string
			UserEmail        string
			Version          string
			Categories       []string
			CategorisedItems map[string][]Item
		}

		catItems := make(map[string][]Item)
		cats := server.iRODSIndex.Categories()
		for _, cat := range cats {
			catItems[cat] = server.iRODSIndex.ItemsInCategory(cat)
		}

		data := pageData{
			LoginURL:         EndPointLogin,
			LogoutURL:        EndPointLogout,
			AuthAvailable:    server.sqyrrlConfig.EnableOIDC,
			Authenticated:    server.isAuthenticated(r),
			UserName:         server.getSessionUserName(r),
			UserEmail:        server.getSessionUserEmail(r),
			Version:          Version,
			Categories:       cats,
			CategorisedItems: catItems,
		}

		tplName := "home.gohtml"
		if err := templates.ExecuteTemplate(w, tplName, data); err != nil {
			logger.Err(err).
				Str("tplName", tplName).
				Msg("Failed to execute HTML template")
		}
	})
}

func HandleLogin(server *SqyrrlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := server.logger
		logger.Trace().Msg("LoginHandler called")

		if !server.sqyrrlConfig.EnableOIDC {
			logger.Error().Msg("OIDC is not enabled")
			writeErrorResponse(logger, w, http.StatusForbidden)
			return
		}

		w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

		state, err := cryptoRandString(16) // Minimum 128 bits required
		if err != nil {
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}
		server.sessionManager.Put(r.Context(), sessionKeyState, state)

		authURL := server.oauth2Config.AuthCodeURL(state)
		logger.Info().
			Str("auth_url", authURL).
			Str("state", state).
			Msg("Redirecting to auth URL")

		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

// HandleAuthCallback is the handler for the authorization callback during OIDC
// Authorization Code Flow. It exchanges the authorization code for an access token.
//
// Much of the implementation is based on the go-oidc examples.
func HandleAuthCallback(server *SqyrrlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := server.logger
		logger.Trace().Msg("AuthCallbackHandler called")

		if !server.sqyrrlConfig.EnableOIDC {
			logger.Error().Msg("OIDC is not enabled")
			writeErrorResponse(logger, w, http.StatusForbidden)
			return
		}

		state := server.sessionManager.GetString(r.Context(), sessionKeyState)
		if state == "" {
			logger.Error().Msg("Failed to get a state cookie")
			writeErrorResponse(logger, w, http.StatusBadRequest)
			return
		}

		query := r.URL.Query()
		if query.Get("state") != state {
			logger.Error().Msg("Response state did not match state cookie")
			writeErrorResponse(logger, w, http.StatusBadRequest)
			return
		}

		responseType := "code" // This is the response type for an Authorization Code flow

		// If implementing PKCE, change here to add a verifier
		oauthToken, err := server.oauth2Config.Exchange(r.Context(), query.Get(responseType))
		if err != nil {
			logger.Err(err).Msg("Failed to exchange an authorization code for an OAuth token")
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}
		logger.Debug().Msg("Successfully exchanged an authorization code for an OAuth token")

		// Extract the ID Token from the OAuth token
		rawIDToken, ok := oauthToken.Extra("id_token").(string)
		if !ok {
			logger.Error().Msg("Failed to get an ID Token from an OAuth token")
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload
		verifier := server.oidcProvider.Verifier(server.oidcConfig)
		var idToken *oidc.IDToken
		if idToken, err = verifier.Verify(context.Background(), rawIDToken); err != nil {
			logger.Err(err).Msg("Failed to verify ID Token")
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}

		// Extract claims from the ID Token
		var claims struct {
			Name          string `json:"name"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err = idToken.Claims(&claims); err != nil {
			logger.Err(err).Msg("Failed to parse ID Token claims")
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}

		// Set session values for the logged-in user. The token is only set in the session
		// if it has been verified
		server.setSessionAccessToken(r.Context(), oauthToken.AccessToken)
		server.setSessionUserEmail(r.Context(), claims.Email)
		server.setSessionUserName(r.Context(), claims.Name)

		logger.Info().
			Str("name", claims.Name).
			Str("email", claims.Email).
			Msg("User logged in")

		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func HandleLogout(server *SqyrrlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := server.logger
		logger.Trace().Msg("LogoutHandler called")

		if !server.sqyrrlConfig.EnableOIDC {
			logger.Error().Msg("OIDC is not enabled")
			writeErrorResponse(logger, w, http.StatusForbidden)
			return
		}

		name := server.getSessionUserName(r)
		email := server.getSessionUserEmail(r)

		if err := server.sessionManager.Destroy(r.Context()); err != nil {
			logger.Err(err).
				Str("name", name).
				Str("email", email).
				Msg("Failed to destroy session")
			writeErrorResponse(logger, w, http.StatusInternalServerError)
			return
		}

		logger.Info().
			Str("name", name).
			Str("email", email).
			Msg("User logged out")

		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func HandleStaticContent(server *SqyrrlServer) http.Handler {
	logger := server.logger
	logger.Trace().Msg("StaticContentHandler called")

	sub := func(dir fs.FS, name string) fs.FS {
		f, err := fs.Sub(dir, name)
		if err != nil {
			logger.Err(err).
				Str("dir", name).
				Msg("Failed to get subdirectory from static content")
		}
		return f
	}
	return http.FileServer(http.FS(sub(staticContentFS, staticContentDir)))
}

func HandleIRODSGet(server *SqyrrlServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := server.logger
		logger.Trace().Msg("iRODS get handler called")

		var corrID string
		if val := r.Context().Value(correlationIDKey); val != nil {
			corrID = val.(string)
		}

		rodsLogger := logger.With().
			Str("correlation_id", corrID).
			Str("irods", "get").Logger()

		// The path should be clean as it has passed through the ServeMux, but since we're
		// doing a path.Join, clean it before passing it to iRODS
		objPath := path.Clean(path.Join("/", r.URL.Path))
		logger.Debug().Str("path", objPath).Msg("Getting iRODS data object")

		getFileRange(rodsLogger, w, r, server.iRODSAccount, objPath)
	})
}

// AddRequestLogger adds an HTTP request suiteLogger to the handler chain.
//
// If a correlation ID is present in the request context, it is logged.
func AddRequestLogger(server *SqyrrlServer) HandlerChain {
	return func(next http.Handler) http.Handler {
		logger := server.logger

		lh := hlog.NewHandler(logger)
		ah := hlog.AccessHandler(func(r *http.Request, status, size int, dur time.Duration) {
			var corrID string
			if val := r.Context().Value(correlationIDKey); val != nil {
				corrID = val.(string)
			}

			hlog.FromRequest(r).Info().
				Str("correlation_id", corrID).
				Dur("duration", dur).
				Int("size", size).
				Int("status", status).
				Str("method", r.Method).
				Str("url", r.URL.RequestURI()).
				Str("remote_addr", r.RemoteAddr).
				Str("forwarded_for", r.Header.Get(HeaderForwardedFor)).
				Str("user_agent", r.UserAgent()).
				Msg("Request served")
		})
		return lh(ah(next))
	}
}

// AddCorrelationID adds a correlation ID to the request context and response headers.
func AddCorrelationID(server *SqyrrlServer) HandlerChain {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := server.logger

			var corrID string
			if corrID = r.Header.Get(HeaderCorrelationID); corrID == "" {
				corrID = xid.New().String()
				logger.Trace().
					Str("correlation_id", corrID).
					Str("url", r.URL.RequestURI()).
					Msg("Creating a new correlation ID")
				w.Header().Add(HeaderCorrelationID, corrID)
			} else {
				logger.Trace().
					Str("correlation_id", corrID).
					Str("url", r.URL.RequestURI()).
					Msg("Using correlation ID from request")
			}

			ctx := context.WithValue(r.Context(), correlationIDKey, corrID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SanitiseRequestURL sanitises the URL path in the request. All requests pass through
// this as a first step.
func SanitiseRequestURL(server *SqyrrlServer) HandlerChain {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := server.logger
			logger.Trace().Str("path", r.URL.Path).Msg("Sanitising URL path")

			// URLs are already cleaned by the Go ServeMux. This is in addition
			dirtyPath := r.URL.Path
			sanPath := userInputPolicy.Sanitize(dirtyPath)
			if sanPath != dirtyPath {
				logger.Warn().
					Str("sanitised_path", sanPath).
					Str("dirty_path", dirtyPath).
					Msg("Path was sanitised")
			}

			url := r.URL
			url.Path = sanPath
			r.URL = url

			next.ServeHTTP(w, r)
		})
	}
}

// cryptoRandString generates a random string of n bytes using the crypto/rand package.
// Implementation copied from the go-oidc examples.
func cryptoRandString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
