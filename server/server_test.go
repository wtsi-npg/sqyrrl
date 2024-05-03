package server_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
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

	When("a server is created", func() {
		It("can be started and stopped", func() {
			srv, err := server.NewSqyrrlServer(suiteLogger, config)
			Expect(err).NotTo(HaveOccurred())

			var startStopErr error

			wgStop := sync.WaitGroup{}
			wgStop.Add(1)
			go func() {
				defer wgStop.Done()
				startStopErr = srv.Start()
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

			srv.Stop()
			wgStop.Wait()

			Expect(startStopErr).NotTo(HaveOccurred())
		})
	})

	When("no iRODS environment file is provided on the command line", func() {
		When("no IRODS_ENVIRONMENT_FILE environment variable is set", func() {
			It("uses the default iRODS environment file path", func() {
				config.EnvFilePath = ""
				srv, err := server.NewSqyrrlServer(suiteLogger, config)
				Expect(err).NotTo(HaveOccurred())

				Expect(srv.IRODSEnvFilePath()).To(Equal(server.LookupIRODSEnvFilePath()))
			})
		})

		When("an IRODS_ENVIRONMENT_FILE environment variable is set", func() {
			It("uses the IRODS_ENVIRONMENT_FILE environment variable", func() {
				envFilePath := config.EnvFilePath
				config.EnvFilePath = ""

				serr := os.Setenv("IRODS_ENVIRONMENT_FILE", envFilePath)
				Expect(serr).NotTo(HaveOccurred())

				srv, err := server.NewSqyrrlServer(suiteLogger, config)
				Expect(err).NotTo(HaveOccurred())

				Expect(srv.IRODSEnvFilePath()).To(Equal(envFilePath))
			})
		})
	})

	When("the configured iRODS environment file is not found", func() {
		It("returns an error", func() {
			config.EnvFilePath = "nonexistent.json"
			srv, err := server.NewSqyrrlServer(suiteLogger, config)
			Expect(err).To(HaveOccurred())
			Expect(srv).To(BeNil())
		})
	})
})
