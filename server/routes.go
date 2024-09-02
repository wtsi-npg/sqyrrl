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
	EndpointStatic = EndpointRoot + "static/"
	EndpointAPI    = EndpointRoot + "api/v1/"

	EndpointLogin        = EndpointAPI + "login/"
	EndpointLogout       = EndpointAPI + "logout/"
	EndpointAuthCallback = EndpointAPI + "auth-callback/"
	EndpointIRODS        = EndpointAPI + "irods/"
)

func (server *SqyrrlServer) addRoutes(mux *http.ServeMux) {
	sm := server.sessionManager

	correlate := AddCorrelationID(server)
	logRequest := AddRequestLogger(server)
	sanitiseURL := SanitiseRequestURL(server)

	getStatic := http.StripPrefix(EndpointStatic, HandleStaticContent(server))
	getObject := http.StripPrefix(EndpointIRODS, HandleIRODSGet(server))

	loginHandler := sm.LoadAndSave(correlate(logRequest(HandleLogin(server))))
	server.addRoute(mux, "GET", EndpointLogin, loginHandler)

	logoutHandler := sm.LoadAndSave(correlate(logRequest(HandleLogout(server))))
	server.addRoute(mux, "POST", EndpointLogout, logoutHandler)

	authCallbackHandler := sm.LoadAndSave(correlate(logRequest(HandleAuthCallback(server))))
	server.addRoute(mux, "GET", EndpointAuthCallback, authCallbackHandler)

	// The static endpoint is used to serve static files from a filesystem embedded in
	// the binary
	staticHandler := sm.LoadAndSave(sanitiseURL(correlate(logRequest(getStatic))))
	server.addRoute(mux, "GET", EndpointStatic, staticHandler)

	// The endpoint used to access files in iRODS
	irodsGetHandler := sm.LoadAndSave(sanitiseURL(correlate(logRequest(getObject))))
	server.addRoute(mux, "GET", EndpointIRODS, irodsGetHandler)

	// The root endpoint hosts a home page. Any requests relative to it are redirected
	// to the API endpoint
	rootHandler := sm.LoadAndSave(sanitiseURL(correlate(logRequest(HandleHomePage(server)))))
	server.addRoute(mux, "GET", EndpointRoot, rootHandler)
}

func (server *SqyrrlServer) addRoute(mux *http.ServeMux, method string, endpoint string,
	handler http.Handler) {
	mux.Handle(method+" "+endpoint, handler)
	server.handlers[endpoint] = handler
}
