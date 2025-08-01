// Derived from code originally published in
//
//	https://github.com/openshift/openshift-tests-private
//
// at commit a6a189840b006da18c8203950983c0cee5ea7354.
package util

import (
	"io"
	"os"

	o "github.com/onsi/gomega"
)

// DuplicateFileToTemp creates a temporary duplicate of the file at srcPath using destPattern for naming,
// returning the path of the duplicate.
func DuplicateFileToTemp(srcPath string, destPrefix string) string {
	destFile, err := os.CreateTemp(os.TempDir(), destPrefix)
	o.Expect(err).NotTo(o.HaveOccurred(), "Failed to create temporary file")
	o.Expect(destFile.Close()).NotTo(o.HaveOccurred(), "Failed to close temporary file")

	destPath := destFile.Name()
	DuplicateFileToPath(srcPath, destPath)
	return destPath
}

// DuplicateFileToPath copies the file at srcPath to destPath.
func DuplicateFileToPath(srcPath string, destPath string) {
	var destFile, srcFile *os.File
	var err error

	srcFile, err = os.Open(srcPath)
	o.Expect(err).NotTo(o.HaveOccurred())
	defer func() {
		o.Expect(srcFile.Close()).NotTo(o.HaveOccurred())
	}()

	// If the file already exists, it is truncated. If the file does not exist, it is created with mode 0666.
	destFile, err = os.Create(destPath)
	o.Expect(err).NotTo(o.HaveOccurred())
	defer func() {
		o.Expect(destFile.Close()).NotTo(o.HaveOccurred())
	}()

	_, err = io.Copy(destFile, srcFile)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(destFile.Sync()).NotTo(o.HaveOccurred())
}
