package controller

import (
	"path/filepath"

	"taa/internal/resource"
)

// ImportIndexRecord 类型别名重定向至 internal/resource
type ImportIndexRecord = resource.ImportIndexRecord

// ImportIndexStore 类型别名重定向至 internal/resource
type ImportIndexStore = resource.ImportIndexStore

// LoadImportIndexStore 代理至 internal/resource
func LoadImportIndexStore(path string) (*ImportIndexStore, error) {
	return resource.LoadImportIndexStore(path)
}

// ImportIndexStore 返回导入索引存储引擎实例
func (s *TAAState) ImportIndexStore() (*ImportIndexStore, error) {
	s.importIndexOnce.Do(func() {
		path := filepath.Join(s.Security.ResultDir, "import-index.json")
		s.importIndex, s.importIndexErr = LoadImportIndexStore(path)
	})
	return s.importIndex, s.importIndexErr
}

func (s *TAAState) importIndexStore() (*ImportIndexStore, error) {
	return s.ImportIndexStore()
}
