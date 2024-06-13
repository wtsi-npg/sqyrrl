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
	EndpointRoot   = "/"
	EndPointStatic = EndpointRoot + "static/"
	EndpointAPI    = EndpointRoot + "api/v1/"

	EndPointLogin        = EndpointAPI + "login/"
	EndPointLogout       = EndpointAPI + "logout/"
	EndpointAuthCallback = EndpointAPI + "auth-callback/"
	EndPointIRODS        = EndpointAPI + "irods/"
)

func (server *SqyrrlServer) addRoutes(mux *http.ServeMux) {
	correlate := AddCorrelationID(server)
	logRequest := AddRequestLogger(server)
	sanitiseURL := SanitiseRequestURL(server)

	getStatic := http.StripPrefix(EndPointStatic, HandleStaticContent(server))
	getObject := http.StripPrefix(EndpointAPI, HandleIRODSGet(server))

	mux.Handle("POST "+EndPointLogin,
		correlate(logRequest(HandleLogin(server))))
	mux.Handle("POST "+EndPointLogout,
		correlate(logRequest(HandleLogout(server))))
	mux.Handle("GET "+EndpointAuthCallback,
		correlate(logRequest(HandleAuthCallback(server))))

	// The static endpoint is used to serve static files from a filesystem embedded in
	// the binary
	mux.Handle("GET "+EndPointStatic,
		sanitiseURL(correlate(logRequest(getStatic))))

	// The endpoint used to access files in iRODS
	mux.Handle(EndPointIRODS,
		sanitiseURL(correlate(logRequest(getObject))))

	// The root endpoint hosts a home page. Any requests relative to it are redirected
	// to the API endpoint
	mux.Handle(EndpointRoot,
		sanitiseURL(correlate(logRequest(HandleHomePage(server)))))
}
