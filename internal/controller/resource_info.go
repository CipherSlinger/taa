package controller

import (
	filetree "taa/filetree"
)

func buildResourceInfoJSON(dataDir string, archivePath ...string) (string, error) {
	opts := filetree.DefaultOptions()
	if len(archivePath) > 0 && archivePath[0] != "" {
		opts.ArchivePath = archivePath[0]
	}
	data, err := filetree.MarshalReport(dataDir, opts)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
