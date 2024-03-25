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
	"net/http"
)

const HTTPHeaderCorrelationID = "X-Correlation-ID"
const HTTPForwardedFor = "X-Forwarded-For"

const HTTPParamPath = "path"

func (server *SqyrrlServer) addRoutes(mux *http.ServeMux) {
	logRequests := addRequestLogger(server.logger)
	correlate := addCorrelationID(server.logger)
	getter := HandleIRODSGet(server.logger, server.account)

	// The /get endpoint is used to retrieve files from iRODS
	mux.Handle("/get", correlate(logRequests(getter)))

	// The home page is currently a placeholder static page showing the version
	mux.Handle("/", correlate(logRequests(HandleHomePage(server.logger))))
}
