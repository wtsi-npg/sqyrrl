package server_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

var _ = Describe("Server startup and shutdown", func() {
	var host, port = "localhost", "3333"
	var config server.Config

	BeforeEach(func() {
		// Test server configuration uses a self-signed certificate for localhost and
		// respected the IRODS_ENVIRONMENT_FILE environment variable to determine the
		// test iRODS server to use.
		configDir := filepath.Join("testdata", "config")
		config = server.Config{
			Host:          host,
			Port:          port,
			CertFilePath:  filepath.Join(configDir, "localhost.crt"),
			KeyFilePath:   filepath.Join(configDir, "localhost.key"),
			EnvFilePath:   filepath.Join(configDir, "test_irods_environment.json"),
			IndexInterval: server.DefaultIndexInterval,
		}
	})

	When("a server instance is created", func() {
		It("can be started and stopped", func() {
			server, err := server.NewSqyrrlServer(suiteLogger, config)
			Expect(err).NotTo(HaveOccurred())

			var startStopErr error

			wgStop := sync.WaitGroup{}
			wgStop.Add(1)
			go func() {
				defer wgStop.Done()
				startStopErr = server.Start()
			}()

			insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
			insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			client := http.Client{Transport: insecureTransport}

			url := url.URL{Scheme: "https", Host: net.JoinHostPort(host, port), Path: "/"}
			homePage := func() (bool, error) {
				r, err := client.Get(url.String())
				if err != nil {
					return false, err
				}
				return r.StatusCode == http.StatusOK, nil
			}

			Eventually(homePage, "5s").Should(BeTrue())
			Expect(startStopErr).NotTo(HaveOccurred())

			server.Stop()
			wgStop.Wait()

			Expect(startStopErr).NotTo(HaveOccurred())
		})
	})
})
