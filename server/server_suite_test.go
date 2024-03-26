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

package server_test

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/rs/zerolog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

var (
	suiteName   = "Sqyrrl Server Test Suite"
	suiteLogger zerolog.Logger

	iRODSEnvFile string
	account      *types.IRODSAccount
	irodsFS      *fs.FileSystem
)

func TestServer(t *testing.T) {
	writer := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	suiteLogger = zerolog.New(writer).With().Timestamp().Logger().Level(zerolog.InfoLevel)

	RegisterFailHandler(Fail)
	RunSpecs(t, suiteName)
}

// Set up the iRODS environment and create a new iRODS filesystem
var _ = BeforeSuite(func() {
	var err error

	iRODSEnvFile = server.IRODSEnvFilePath()
	manager, err := server.NewICommandsEnvironmentManager()
	Expect(err).NotTo(HaveOccurred())

	err = manager.SetEnvironmentFilePath(iRODSEnvFile)
	Expect(err).NotTo(HaveOccurred())

	err = server.InitIRODS(manager, "irods")
	Expect(err).NotTo(HaveOccurred())

	account, err = server.NewIRODSAccount(suiteLogger, manager)
	Expect(err).NotTo(HaveOccurred())

	irodsFS, err = fs.NewFileSystemWithDefault(account, suiteName)
	Expect(err).NotTo(HaveOccurred())

	dir, err := os.Getwd()
	Expect(err).NotTo(HaveOccurred())

	defer func(dir string) {
		err := os.Chdir(dir)
		if err != nil {
			suiteLogger.Err(err).
				Str("path", dir).
				Msg("Failed to chdir back to the original working directory after " +
					"setting up HTML templates")
		}
	}(dir)

	// For the tests, make sure that the initial invocation of server. GetTemplates is
	// done from a directory where the templates are located and not in the subdirectory
	// where the tests are being run (because the templates are not there).
	err = os.Chdir("..")
	Expect(err).NotTo(HaveOccurred())

	server.GetTemplates()
})

// Release the iRODS filesystem
var _ = AfterSuite(func() {
	irodsFS.Release()
})

// Return a new pseudo-randomised path in iRODS
func TmpRodsPath(root string, prefix string) string {
	s := rand.NewSource(GinkgoRandomSeed())
	r := rand.New(s)
	d := fmt.Sprintf("%s.%d.%010d", prefix, os.Getpid(), r.Uint32())
	return filepath.Join(root, d)
}
