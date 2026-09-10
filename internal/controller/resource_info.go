package controller

import (
	filetree "taa/pkg/filetree"
)

func buildResourceInfoJSON(dataDir, archivePath string) (string, error) {
	opts := filetree.DefaultOptions()
	if archivePath != "" {
		opts.ArchivePath = archivePath
	}
	data, err := filetree.MarshalReport(dataDir, opts)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
