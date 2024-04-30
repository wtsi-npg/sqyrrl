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
	"github.com/rs/xid"
	"github.com/rs/zerolog/hlog"
	"io/fs"
	"net/http"
	"path"
	"time"

	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/rs/zerolog"
)

// HandlerChain is a function that takes an http.Handler and returns a new http.Handler
// wrapping the input handler. Each handler in the chain should process the request in
// some way, and then call the next handler. Ideally, the functionality of each handler
// should be orthogonal to the others.
//
// This is sometimes called "middleware" in Go. I haven't used that term here because it
// already has an established meaning in the context of operating systems and networking.
type HandlerChain func(http.Handler) http.Handler

// HandleHomePage is a handler for the static home page.
func HandleHomePage(logger zerolog.Logger, index *ItemIndex) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Trace().Msg("HomeHandler called")

		requestPath := r.URL.Path

		if requestPath != "/" {
			redirect := path.Join(EndpointAPI, requestPath)
			logger.Trace().
				Str("from", requestPath).
				Str("to", redirect).
				Msg("Redirecting to API")
			http.Redirect(w, r, redirect, http.StatusPermanentRedirect)
		}

		type pageData struct {
			Version          string
			Categories       []string
			CategorisedItems map[string][]Item
		}

		catItems := make(map[string][]Item)
		cats := index.Categories()
		for _, cat := range cats {
			catItems[cat] = index.ItemsInCategory(cat)
		}

		data := pageData{
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

func HandleStaticContent(logger zerolog.Logger) http.Handler {
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

func HandleIRODSGet(logger zerolog.Logger, account *types.IRODSAccount) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		getFileRange(rodsLogger, w, r, account, objPath)
	})
}

// AddRequestLogger adds an HTTP request suiteLogger to the handler chain.
//
// If a correlation ID is present in the request context, it is logged.
func AddRequestLogger(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
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
func AddCorrelationID(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
func SanitiseRequestURL(logger zerolog.Logger) HandlerChain {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
