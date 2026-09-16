package resource

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	teecrypto "taa/pkg/crypto"
)

// DecryptResourceEnvelope 从磁盘密文文件中读取国密 SM2+SM4-GCM 封装密文并解密，
// 将明文写入临时文件并返回路径。调用方在使用完毕后负责删除临时文件。
func DecryptResourceEnvelope(privKey *teecrypto.SM2PrivateKey, ciphertextPath string) (string, error) {
	if privKey == nil {
		return "", fmt.Errorf("SM2 private key is required for decryption")
	}

	f, err := os.Open(ciphertextPath)
	if err != nil {
		return "", fmt.Errorf("打开密文文件: %w", err)
	}
	defer f.Close()

	sealed, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("读取密文: %w", err)
	}

	plaintext, err := teecrypto.OpenSM2SM4GCM(privKey, sealed)
	sealed = nil // 及时释放密文内存
	if err != nil {
		return "", err
	}

	out, err := os.CreateTemp("", "taa-plaintext-*")
	if err != nil {
		plaintext = nil
		return "", fmt.Errorf("创建明文临时文件: %w", err)
	}
	plainPath := out.Name()
	if _, err := out.Write(plaintext); err != nil {
		_ = out.Close()
		_ = os.Remove(plainPath)
		plaintext = nil
		return "", fmt.Errorf("写入明文临时文件: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(plainPath)
		return "", fmt.Errorf("关闭明文临时文件: %w", err)
	}

	return plainPath, nil
}

// EncryptDataEnvelope 使用指定公钥对数据进行国密 SM2+SM4-GCM 信封加密
func EncryptDataEnvelope(pubKeyPEM string, plaintext []byte) ([]byte, error) {
	pub, err := teecrypto.ParseSM2PublicKeyPEM([]byte(pubKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("publicKey 解析失败: %w", err)
	}
	sealed, err := teecrypto.SealSM2SM4GCM(pub, plaintext)
	if err != nil {
		return nil, fmt.Errorf("加密失败: %w", err)
	}
	return sealed, nil
}

// CompressDirToZip 将目录压缩为 zip 格式的字节切片，并对软链接进行越界安全校验
func CompressDirToZip(srcDir string) ([]byte, error) {
	srcDir = filepath.Clean(srcDir)
	info, err := os.Stat(srcDir)
	if err != nil {
		return nil, fmt.Errorf("目录不存在: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("路径不是目录: %s", srcDir)
	}

	evalSrcDir, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		evalSrcDir = srcDir
	}
	cleanSrcDir := filepath.Clean(evalSrcDir)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	baseDir := filepath.Dir(srcDir)
	fileCount := 0
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("访问文件失败 %s: %w", path, err)
		}

		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return fmt.Errorf("计算相对路径失败 %s: %w", path, err)
		}
		relPath = filepath.ToSlash(relPath)

		if info.Mode()&os.ModeSymlink != 0 {
			evalPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("解析物理路径失败 %s: %w", path, err)
			}
			cleanEval := filepath.Clean(evalPath)
			if cleanEval != cleanSrcDir && !strings.HasPrefix(cleanEval, cleanSrcDir+string(filepath.Separator)) {
				return fmt.Errorf("检测到非法越界软链接: %s -> %s", path, evalPath)
			}

			linkTarget, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("读取软链接目标失败 %s: %w", path, err)
			}
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return fmt.Errorf("创建软链接 header 失败 %s: %w", path, err)
			}
			header.Name = relPath
			header.Method = zip.Store
			w, err := zw.CreateHeader(header)
			if err != nil {
				return fmt.Errorf("写入软链接 header 失败 %s: %w", path, err)
			}
			if _, err := io.WriteString(w, linkTarget); err != nil {
				return fmt.Errorf("写入软链接内容失败 %s: %w", path, err)
			}
			fileCount++
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("创建 header 失败 %s: %w", path, err)
		}

		if info.IsDir() {
			header.Name = strings.TrimSuffix(relPath, "/") + "/"
			header.Method = zip.Store
			if _, err := zw.CreateHeader(header); err != nil {
				return fmt.Errorf("写入目录 header 失败 %s: %w", path, err)
			}
			return nil
		}

		header.Name = relPath
		header.Method = zip.Deflate

		w, err := zw.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("写入文件 header 失败 %s: %w", path, err)
		}

		fileCount++
		if err := func() error {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("打开文件失败 %s: %w", path, err)
			}
			defer f.Close()

			if _, err := io.Copy(w, f); err != nil {
				return fmt.Errorf("复制文件内容失败 %s: %w", path, err)
			}
			return nil
		}(); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	log.Printf("compressDirToZip: 共压缩 %d 个文件", fileCount)
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
