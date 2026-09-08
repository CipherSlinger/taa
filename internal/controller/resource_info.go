package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	filetree "taa/filetree"
)

func buildResourceInfoJSON(dataDir string) (string, error) {
	data, err := filetree.MarshalReport(dataDir, filetree.DefaultOptions())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *TAAState) loadResourceDataset(ctx context.Context, dataDir string, includeDataDir bool) (map[string]any, error) {
	if !includeDataDir {
		return map[string]any{}, nil
	}
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("data dir is required")
	}

	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	data, err := filetree.MarshalReport(dataDir, filetree.DefaultOptions())
	if err != nil {
		return nil, err
	}

	var dataset map[string]any
	if err := json.Unmarshal(data, &dataset); err != nil {
		return nil, fmt.Errorf("parse resource info JSON: %w", err)
	}
	if dataset == nil {
		dataset = map[string]any{}
	}
	return dataset, nil
}
