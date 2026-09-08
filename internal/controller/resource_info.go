package controller

import (
	filetree "taa/filetree"
)

func buildResourceInfoJSON(dataDir string) (string, error) {
	data, err := filetree.MarshalReport(dataDir, filetree.DefaultOptions())
	if err != nil {
		return "", err
	}
	return string(data), nil
}
