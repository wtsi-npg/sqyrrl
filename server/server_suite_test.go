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

	projectDir, workDir string

	iRODSEnvFile string
	account      *types.IRODSAccount
	irodsFS      *fs.FileSystem
)

func TestSuite(t *testing.T) {
	writer := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	suiteLogger = zerolog.New(writer).With().Timestamp().Logger().Level(zerolog.InfoLevel)

	RegisterFailHandler(Fail)
	RunSpecs(t, suiteName)
}

// Set up the iRODS environment and create a new iRODS filesystem
var _ = BeforeSuite(func() {
	var err error

	workDir, err = os.Getwd()
	Expect(err).NotTo(HaveOccurred())

	projectDir = filepath.Join("..", workDir)

	iRODSEnvFile = server.IRODSEnvFilePath()
	manager, err := server.NewICommandsEnvironmentManager()
	Expect(err).NotTo(HaveOccurred())

	err = manager.SetEnvironmentFilePath(iRODSEnvFile)
	Expect(err).NotTo(HaveOccurred())

	err = os.Setenv(server.IRODSPasswordEnvVar, "irods")
	Expect(err).NotTo(HaveOccurred())
	authFilePath := manager.GetPasswordFilePath()
	err = server.InitIRODS(suiteLogger, authFilePath, os.Getenv(server.IRODSPasswordEnvVar))
	Expect(err).NotTo(HaveOccurred())

	account, err = server.NewIRODSAccount(suiteLogger, manager)
	Expect(err).NotTo(HaveOccurred())

	irodsFS, err = fs.NewFileSystemWithDefault(account, suiteName)
	Expect(err).NotTo(HaveOccurred())
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
