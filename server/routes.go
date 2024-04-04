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

const (
	HeaderCorrelationID = "X-Correlation-ID"
	HeaderForwardedFor  = "X-Forwarded-For"
)

const (
	EndpointRoot    = "/"
	EndPointFavicon = "/favicon.ico"
	EndpointAPI     = EndpointRoot + "api/v1/"
)

func (server *SqyrrlServer) addRoutes(mux *http.ServeMux) {
	logRequest := AddRequestLogger(server.logger)
	correlate := AddCorrelationID(server.logger)
	getObject := http.StripPrefix(EndpointAPI, HandleIRODSGet(server.logger, server.account))

	// The home page is currently a placeholder static page showing the version
	//
	// Any requests relative to the root are redirected to the API endpoint
	mux.Handle("GET "+EndpointRoot, correlate(logRequest(HandleHomePage(server.logger))))

	// There is no favicon, this is just to log requests
	mux.Handle("GET "+EndPointFavicon, logRequest(http.NotFoundHandler()))

	// The API endpoint is used to access files in iRODS
	mux.Handle("GET "+EndpointAPI, correlate(logRequest(getObject)))
}
