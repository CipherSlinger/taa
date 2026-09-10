package crypto

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CreateTarGzArchive 创建 tar.gz 归档文件
// sources: 要归档的文件或文件夹路径列表
// outputPath: 输出的 tar.gz 文件路径
func CreateTarGzArchive(sources []string, outputPath string) error {
	if len(sources) == 0 {
		return fmt.Errorf("没有要归档的源文件")
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer outFile.Close()

	return CreateTarGzArchiveWriter(sources, outFile)
}

// CreateTarGzArchiveWriter 将 sources 写成 tar.gz 归档到 w。
func CreateTarGzArchiveWriter(sources []string, w io.Writer) error {
	if len(sources) == 0 {
		return fmt.Errorf("没有要归档的源文件")
	}

	// 创建 gzip 压缩 writer
	gzWriter := gzip.NewWriter(w)
	defer gzWriter.Close()

	// 创建 tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// 遍历所有源路径
	for _, source := range sources {
		source = filepath.Clean(source)
		info, err := os.Stat(source)
		if err != nil {
			return fmt.Errorf("访问源路径失败 %s: %w", source, err)
		}

		if info.IsDir() {
			// 处理文件夹
			err = addDirToTar(tarWriter, source, info.Name())
			if err != nil {
				return fmt.Errorf("添加文件夹到归档失败 %s: %w", source, err)
			}
		} else {
			// 处理单个文件
			err = addFileToTar(tarWriter, source, info.Name())
			if err != nil {
				return fmt.Errorf("添加文件到归档失败 %s: %w", source, err)
			}
		}
	}

	return nil
}

// ExtractTarGzArchive 解压 tar.gz 归档文件
// tarGzPath: tar.gz 文件路径
// outputDir: 解压输出目录
func ExtractTarGzArchive(tarGzPath string, outputDir string) error {
	inFile, err := os.Open(tarGzPath)
	if err != nil {
		return fmt.Errorf("打开归档文件失败: %w", err)
	}
	defer inFile.Close()
	return ExtractTarGzReader(inFile, outputDir)
}

// ExtractTarGzReader extracts a tar.gz archive from an io.Reader into
// outputDir. Use this when the gzip data is already in memory to avoid a
// temporary file round-trip.
func ExtractTarGzReader(r io.Reader, outputDir string) error {
	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("创建 gzip reader 失败: %w", err)
	}
	defer gzReader.Close()

	// 创建 tar reader
	tarReader := tar.NewReader(gzReader)

	// 确保输出目录存在
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	cleanOutputDir := filepath.Clean(outputDir)

	// 逐个解压文件
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // 归档结束
		}
		if err != nil {
			return fmt.Errorf("读取归档失败: %w", err)
		}

		// 构建输出路径
		targetPath := filepath.Join(outputDir, header.Name)

		// 安全检查：防止路径遍历攻击
		if !strings.HasPrefix(filepath.Clean(targetPath), cleanOutputDir) {
			return fmt.Errorf("检测到不安全的路径: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// 创建目录
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("创建目录失败 %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			// 创建文件
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("创建父目录失败 %s: %w", filepath.Dir(targetPath), err)
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("创建文件失败 %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("写入文件失败 %s: %w", targetPath, err)
			}
			outFile.Close()
		}
	}

	return nil
}

// addDirToTar 递归添加文件夹到 tar 归档
func addDirToTar(tarWriter *tar.Writer, sourcePath string, baseName string) error {
	return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 创建 tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("创建 tar header 失败: %w", err)
		}

		// 设置相对路径（使用 baseName 作为根目录名）
		relPath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return fmt.Errorf("计算相对路径失败: %w", err)
		}
		if relPath == "." {
			header.Name = baseName
		} else {
			header.Name = filepath.Join(baseName, relPath)
		}

		// 写入 header
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("写入 tar header 失败: %w", err)
		}

		// 如果是普通文件，写入文件内容
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("打开文件失败 %s: %w", path, err)
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return fmt.Errorf("写入文件内容失败 %s: %w", path, err)
			}
		}

		return nil
	})
}

// ExtractZipArchive extracts a zip archive from an in-memory byte slice into
// outputDir. It includes path-traversal protection identical to the tar.gz
// extractor above.
func ExtractZipArchive(data []byte, outputDir string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("打开 zip 归档失败: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	cleanOutputDir := filepath.Clean(outputDir)

	for _, f := range r.File {
		targetPath := filepath.Join(outputDir, f.Name)

		// Security: prevent path traversal (e.g. ../../etc/passwd)
		if !strings.HasPrefix(filepath.Clean(targetPath), cleanOutputDir) {
			return fmt.Errorf("检测到不安全的路径: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, f.Mode()); err != nil {
				return fmt.Errorf("创建目录失败 %s: %w", targetPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("创建父目录失败 %s: %w", filepath.Dir(targetPath), err)
		}

		outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("创建文件失败 %s: %w", targetPath, err)
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return fmt.Errorf("打开归档内文件失败 %s: %w", f.Name, err)
		}

		_, copyErr := io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if copyErr != nil {
			return fmt.Errorf("写入文件失败 %s: %w", targetPath, copyErr)
		}
	}

	return nil
}

// addFileToTar 添加单个文件到 tar 归档
func addFileToTar(tarWriter *tar.Writer, sourcePath string, nameInArchive string) error {
	// 打开文件
	file, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	// 获取文件信息
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}

	// 创建 tar header
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("创建 tar header 失败: %w", err)
	}
	header.Name = nameInArchive

	// 写入 header
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("写入 tar header 失败: %w", err)
	}

	// 写入文件内容
	if _, err := io.Copy(tarWriter, file); err != nil {
		return fmt.Errorf("写入文件内容失败: %w", err)
	}

	return nil
}
