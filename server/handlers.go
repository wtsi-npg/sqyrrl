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
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/rs/zerolog"
	"net/http"
	"path"
)

// HandleHomePage is a handler for the static home page.
func HandleHomePage(logger zerolog.Logger) http.Handler {
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

		type customData struct {
			URL     string
			Version string
		}

		data := customData{Version: Version, URL: r.URL.RequestURI()}

		tplName := "home.gohtml"
		if err := GetTemplates().ExecuteTemplate(w, tplName, data); err != nil {
			logger.Err(err).
				Str("tplName", tplName).
				Msg("Failed to execute HTML template")
		}
	})
}

func HandleIRODSGet(logger zerolog.Logger, account *types.IRODSAccount) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Trace().Msg("iRODS get handler called")

		var corrID string
		if val := r.Context().Value(correlationIDKey); val != nil {
			corrID = val.(string)
		}

		dirtyPath := r.URL.Path
		sanPath := userInputPolicy.Sanitize(dirtyPath)
		if sanPath != dirtyPath {
			logger.Warn().
				Str("correlation_id", corrID).
				Str("sanitised_path", sanPath).
				Str("dirty_path", dirtyPath).
				Msg("Path was sanitised")
		}

		rodsLogger := logger.With().
			Str("correlation_id", corrID).
			Str("irods", "get").Logger()

		sanPath = path.Clean("/" + sanPath)
		logger.Debug().Str("path", sanPath).Msg("Getting iRODS data object")

		getFileRange(rodsLogger, w, r, account, sanPath)
	})
}
