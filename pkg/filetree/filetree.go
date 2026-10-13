// filetree — 目录树解析工具（多模态数据集 → JSON）
// ================================================================
// 扫描一个数据集目录，按魔数（magic bytes）识别文件格式（不信扩展名），
// 对结构化文件就地解析 schema 与数据量，输出一棵带标注的目录树 JSON。
//
// 覆盖格式：CSV / TSV / XLSX / JSON / JSONL / SQLite / Parquet(仅识别)
//
//	PNG / JPEG / GIF / WEBP / PDF / ZIP / GZIP / 纯文本
//
// 设计约束（面向 TEE 侧部署）：
//   - CSV/JSONL 逐行流式读取，内存占用与文件大小无关
//   - 单文件解析上限（默认 128MB）与文件总数上限（默认 100000），防 zip bomb / 恶意超大输入
//   - 单个文件解析失败只降级为警告标注，不中断整棵树
//
// 该包只提供库接口，由上层应用直接调用。
package filetree

import (
	"archive/zip"
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	goparquet "github.com/fraugster/parquet-go"
	"github.com/xuri/excelize/v2"
	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，无 CGO 依赖

	teecrypto "taa/pkg/crypto"
)

const (
	toolVersion = "1.0.0"
	headSize    = 512     // 魔数探测读取的头部字节数
	sniffSize   = 1 << 20 // 文本嗅探上限 1MB

	// PreviewRows 表格类文件预览的最大行数
	PreviewRows = 5
	// previewCellRunes 预览单元格的最大字符数，超出部分截断并追加省略号
	previewCellRunes = 128
)

// TableInfo SQLite 内单张表的信息
type TableInfo struct {
	Name    string  `json:"name"`
	Rows    int64   `json:"rows"`
	Columns []Field `json:"columns,omitempty"` // 列定义，与 Preview 的行按位置对齐
	Preview [][]any `json:"preview,omitempty"` // 前 PreviewRows 行数据
}

// Field 描述结构化文件里的一个字段
type Field struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Node 目录树节点：目录与文件统一结构，文件无 children
type Node struct {
	Name string `json:"name"`
	Type string `json:"type"` // "dir" | "file"

	// 文件属性
	Format   string      `json:"fmt,omitempty"` // 魔数探测出的格式标签
	Size     int64       `json:"size,omitempty"`
	Rows     *int64      `json:"rows,omitempty"`     // 数值型行/条数（前端可排序）
	IsObject bool        `json:"isObject,omitempty"` // JSON 是否为对象
	Fields   []Field     `json:"fields,omitempty"`   // schema：顶层字段/表头
	Tables   []TableInfo `json:"tables,omitempty"`   // SQLite 表级明细
	Warning  string      `json:"warning,omitempty"`  // 解析失败/截断等警告

	// 目录属性
	FileCount int     `json:"file_count,omitempty"` // 目录下（递归）文件总数
	Children  []*Node `json:"children,omitempty"`

	// 表格类文件的前 PreviewRows 行数据；每行是一个数组，与 Fields 按位置对齐
	Preview [][]any `json:"preview,omitempty"`
}

// FormatStat 格式分布统计
type FormatStat struct {
	Format  string `json:"format"`
	Count   int    `json:"count"`
	SizeSum int64  `json:"size_sum"`
}

// ChecksumInfo 描述资源归档或数据集的完整性校验和信息
type ChecksumInfo struct {
	Size      int64  `json:"size,omitempty"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Report 最终 JSON 报告
type Report struct {
	Version     string        `json:"version"`
	GeneratedAt string        `json:"generated_at"`
	TotalFiles  int           `json:"total_files"`
	TotalSize   int64         `json:"total_size"`
	TotalSizeH  string        `json:"total_size_h"`
	Structured  int           `json:"structured_files"` // 成功解析出 schema/行数的文件数
	Warnings    []string      `json:"warnings,omitempty"`
	ByFormat    []FormatStat  `json:"by_format"`
	Checksum    *ChecksumInfo `json:"checksum,omitempty"`
	Tree        *Node         `json:"tree"`
}

// Options 控制扫描上限与校验和计算。
type Options struct {
	MaxFiles      int
	MaxParseBytes int64
	ArchivePath   string        // 可选：明文压缩包路径；若提供，优先计算该归档包的 SM3 校验和（与 import 接口逻辑一致）
	Checksum      *ChecksumInfo // 可选：直接注入的校验和信息
	// SkipChecksum 可选：不计算任何校验和，Report.Checksum 保持 nil。默认关闭——
	// 既没给 Checksum 也没给 ArchivePath 时，BuildReport 会回落到整目录 SM3 重读，
	// 只取目录结构的调用方（如训练报告的 result_files，那里不序列化 checksum）应打开它。
	SkipChecksum bool
	// IncludePreview 可选：为表格类文件生成前 PreviewRows 行预览。默认关闭——
	// 预览会把真实数据值带进输出，只有一次性应答（如 getResourceInfo）才应打开它；
	// 报告类产物会落盘并随导出接口外发，必须保持关闭。
	IncludePreview bool
}

// DefaultOptions 返回与 CLI 相同的默认扫描参数。
func DefaultOptions() Options {
	return Options{
		MaxFiles:      100000,
		MaxParseBytes: 128 << 20,
	}
}

// computeFileSM3 计算单个归档文件的 SM3 校验和与大小（与 import 数据导入接口对压缩包计算 SM3 哈希的逻辑一致）
func computeFileSM3(path string) (*ChecksumInfo, error) {
	size, hex, err := teecrypto.HashFileSM3(path)
	if err != nil {
		return nil, fmt.Errorf("hash file for sm3: %w", err)
	}
	return &ChecksumInfo{
		Size:      size,
		Algorithm: "sm3",
		Value:     hex,
	}, nil
}

// computeDirectorySM3 计算目录下所有常规文件（按相对路径排序）的流式 SM3 校验和与累计大小
func computeDirectorySM3(dir string) (*ChecksumInfo, error) {
	var files []struct {
		path string
		size int64
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil
		}
		files = append(files, struct {
			path string
			size int64
		}{path: path, size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk dir for sm3: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	h := teecrypto.NewSM3()
	var totalSize int64
	buf := make([]byte, 64*1024)

	for _, file := range files {
		rel, err := filepath.Rel(dir, file.path)
		if err != nil {
			return nil, fmt.Errorf("resolve rel path for %s: %w", file.path, err)
		}
		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})
		totalSize += file.size

		f, err := os.Open(file.path)
		if err != nil {
			return nil, fmt.Errorf("open file %s: %w", file.path, err)
		}
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				f.Close()
				return nil, fmt.Errorf("read file %s: %w", file.path, rerr)
			}
		}
		f.Close()
	}

	return &ChecksumInfo{
		Size:      totalSize,
		Algorithm: "sm3",
		Value:     fmt.Sprintf("%x", h.Sum(nil)),
	}, nil
}

// BuildReport 扫描数据集目录并返回完整报告。
func BuildReport(root string, opts Options) (*Report, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("路径错误: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("不是有效目录: %s", root)
	}

	if opts.MaxFiles <= 0 {
		opts.MaxFiles = DefaultOptions().MaxFiles
	}
	if opts.MaxParseBytes <= 0 {
		opts.MaxParseBytes = DefaultOptions().MaxParseBytes
	}

	s := &scanner{
		root:     abs,
		maxFiles: opts.MaxFiles,
		maxParse: opts.MaxParseBytes,
		preview:  opts.IncludePreview,
		byFormat: map[string]*FormatStat{},
	}
	tree, err := s.scan(abs, "")
	if err != nil {
		return nil, err
	}
	tree.Name = filepath.Base(abs)

	formats := make([]FormatStat, 0, len(s.byFormat))
	for _, v := range s.byFormat {
		formats = append(formats, *v)
	}
	sort.Slice(formats, func(i, j int) bool { return formats[i].Count > formats[j].Count })

	var checksum *ChecksumInfo
	switch {
	case opts.Checksum != nil:
		checksum = opts.Checksum
	case opts.ArchivePath != "":
		c, err := computeFileSM3(opts.ArchivePath)
		if err != nil {
			return nil, fmt.Errorf("计算归档包 SM3 校验和失败: %w", err)
		}
		checksum = c
	case !opts.SkipChecksum:
		c, err := computeDirectorySM3(abs)
		if err == nil {
			checksum = c
		}
	}

	return &Report{
		Version:     toolVersion,
		GeneratedAt: time.Now().Format(time.RFC3339),
		TotalFiles:  s.fileCount,
		TotalSize:   s.totalSize,
		TotalSizeH:  humanSize(s.totalSize),
		Structured:  s.structured,
		Warnings:    s.warnings,
		ByFormat:    formats,
		Checksum:    checksum,
		Tree:        tree,
	}, nil
}

// MarshalReport 扫描数据集目录并直接返回 JSON。
func MarshalReport(root string, opts Options) ([]byte, error) {
	report, err := BuildReport(root, opts)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ---------------------------------------------------------------------------
// 魔数探测
// ---------------------------------------------------------------------------

var (
	magicPNG    = []byte{0x89, 'P', 'N', 'G'}
	magicJPEG   = []byte{0xFF, 0xD8, 0xFF}
	magicGIF    = []byte("GIF8")
	magicBMP    = []byte("BM")
	magicRIFF   = []byte("RIFF")
	magicWEBP   = []byte("WEBP")
	magicPDF    = []byte("%PDF")
	magicGZIP   = []byte{0x1F, 0x8B}
	magicPK     = []byte("PK\x03\x04")
	magicSQLite = []byte("SQLite format 3\x00")
	magicParq1  = []byte("PAR1")
)

// IsArchiveFile 检查文件是否为已知明文压缩包格式（ZIP / GZIP / TAR）。
func IsArchiveFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	hdr := make([]byte, 512)
	n, err := f.Read(hdr)
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	if n >= 2 {
		if hdr[0] == 0x50 && hdr[1] == 0x4B {
			return true, nil
		}
		if hdr[0] == 0x1F && hdr[1] == 0x8B {
			return true, nil
		}
	}
	if n >= 262 && bytes.Equal(hdr[257:262], []byte("ustar")) {
		return true, nil
	}
	return false, nil
}

// detectFormat 基于头部魔数判断格式；文本类继续细分。
// ext 仅作文本细分参考，二进制格式完全由魔数决定。
func detectFormat(head []byte, path string) string {
	if len(head) == 0 {
		return classifyByExt(path)
	}
	switch {
	case bytes.HasPrefix(head, magicPNG):
		return "png"
	case bytes.HasPrefix(head, magicJPEG):
		return "jpeg"
	case bytes.HasPrefix(head, magicGIF):
		return "gif"
	case bytes.HasPrefix(head, magicBMP):
		return "bmp"
	case bytes.HasPrefix(head, magicSQLite):
		return "sqlite"
	case bytes.HasPrefix(head, magicPDF):
		return "pdf"
	case bytes.HasPrefix(head, magicGZIP):
		return "gzip"
	case bytes.HasPrefix(head, magicParq1):
		return "parquet"
	case bytes.HasPrefix(head, magicPK):
		return classifyZip(path)
	case bytes.HasPrefix(head, magicRIFF):
		if len(head) >= 12 && bytes.Equal(head[8:12], magicWEBP) {
			return "webp"
		}
		if len(head) >= 12 {
			switch string(head[8:12]) {
			case "WAVE":
				return "wav"
			case "AVI ":
				return "avi"
			}
		}
		return "riff"
	}
	// 文本类细分
	if isText(head) {
		return classifyText(path)
	}
	return classifyByExt(path)
}

func classifyByExt(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".csv", ".tsv":
		return "csv"
	case ".json":
		return "json"
	case ".jsonl":
		return "jsonl"
	case ".xlsx":
		return "xlsx"
	case ".parquet":
		return "parquet"
	case ".db", ".sqlite":
		return "sqlite"
	case ".md", ".markdown":
		return "md"
	case ".txt":
		return "txt"
	case ".yaml", ".yml":
		return "yaml"
	case ".pdf":
		return "pdf"
	case ".gif":
		return "gif"
	case ".png":
		return "png"
	case ".jpg", ".jpeg":
		return "jpeg"
	case ".webp":
		return "webp"
	case ".zip":
		return "zip"
	case ".gz":
		return "gzip"
	default:
		return "txt"
	}
}

// classifyZip PK 魔数下按 zip 内部结构细分为 xlsx / docx / 通用 zip
func classifyZip(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "zip"
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "zip"
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return "zip"
	}
	hasCT, hasXL, hasWord := false, false, false
	for _, zf := range zr.File {
		if zf.Name == "[Content_Types].xml" {
			hasCT = true
		}
		if strings.HasPrefix(zf.Name, "xl/") {
			hasXL = true
		}
		if strings.HasPrefix(zf.Name, "word/") {
			hasWord = true
		}
	}
	if hasCT && hasXL {
		return "xlsx"
	}
	if hasCT && hasWord {
		return "docx"
	}
	return "zip"
}

// isText 粗判是否为可读文本：UTF-8 合法且不可打印字节占比低
func isText(head []byte) bool {
	if len(head) == 0 {
		return true
	}
	nul := 0
	for _, b := range head {
		if b == 0x00 {
			nul++
		}
	}
	if float64(nul)/float64(len(head)) > 0.05 {
		return false
	}
	return utf8.Valid(head)
}

// classifyText 文本细分：csv / json / jsonl / txt / md / yaml
func classifyText(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return classifyByExt(path)
	}
	defer f.Close()

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".md", ".markdown":
		return "md"
	case ".txt":
		return "txt"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".jsonl":
		return "jsonl"
	case ".csv", ".tsv":
		return "csv"
	}

	br := bufio.NewReader(io.LimitReader(f, sniffSize))
	first, err := br.ReadString('\n')
	first = strings.TrimRight(first, "\r\n")
	if err != nil && first == "" {
		return classifyByExt(path)
	}

	trimmed := strings.TrimSpace(first)
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") && json.Valid([]byte(trimmed)) {
		rest, _ := br.ReadString('\n')
		rest = strings.TrimSpace(rest)
		if rest != "" {
			return "jsonl"
		}
		return "json"
	}
	if strings.ContainsAny(first, ",;\t") {
		return "csv"
	}
	return classifyByExt(path)
}

type typeState struct {
	typeName string
}

func updateTypeState(states map[string]*typeState, field, typ string) {
	if typ == "" {
		return
	}
	s := states[field]
	if s == nil {
		s = &typeState{}
		states[field] = s
	}
	s.typeName = mergeTypes(s.typeName, typ)
}

func mergeTypes(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if a == b {
		return a
	}
	if a == "str" || b == "str" {
		return "str"
	}
	if (a == "object" || a == "list") || (b == "object" || b == "list") {
		return "str"
	}
	if (a == "int" && b == "float") || (a == "float" && b == "int") {
		return "float"
	}
	if (a == "date" && b == "datetime") || (a == "datetime" && b == "date") {
		return "datetime"
	}
	if a == "bool" && b == "bool" {
		return "bool"
	}
	return "str"
}

func finalType(states map[string]*typeState, field string) string {
	if s := states[field]; s != nil && s.typeName != "" {
		return s.typeName
	}
	return "str"
}

func int64Ptr(v int64) *int64 {
	return &v
}

func finalizeFields(order []string, states map[string]*typeState) []Field {
	fields := make([]Field, len(order))
	for i, name := range order {
		fields[i] = Field{Name: name, Type: finalType(states, name)}
	}
	return fields
}

func detectScalarType(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	if lower == "true" || lower == "false" {
		return "bool"
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02 15:04:05Z07:00"} {
		if _, err := time.Parse(layout, s); err == nil {
			return "datetime"
		}
	}
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return "date"
	}
	return "str"
}

func inferJSONValueType(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return inferJSONTextType(x)
	case json.Number:
		return inferNumberType(x.String())
	case float64:
		return inferNumberType(strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		return "bool"
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "list"
	default:
		return inferJSONTextType(fmt.Sprint(x))
	}
}

func inferJSONTextType(s string) string {
	return detectScalarType(s)
}

func inferNumberType(s string) string {
	if strings.ContainsAny(s, ".eE") {
		if _, err := strconv.ParseFloat(s, 64); err == nil {
			return "float"
		}
		return "str"
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return "int"
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return "float"
	}
	return "str"
}

func inferTextType(s string) string {
	typ := detectScalarType(s)
	if typ != "str" {
		return typ
	}
	if typ := inferNumberType(s); typ != "str" {
		return typ
	}
	return "str"
}

// decodeJSONObject 遍历单个 JSON 对象的键值，汇总字段顺序与类型。collect 为真时
// 一并返回解码出的键值，供调用方在字段顺序确定后回填预览——值本来就要解出来判类型，
// 顺带留下即可，不必为同一元素再解一遍。
func decodeJSONObject(dec *json.Decoder, collect bool) ([]string, map[string]*typeState, map[string]any, error) {
	order := make([]string, 0)
	states := map[string]*typeState{}
	var obj map[string]any
	if collect {
		obj = make(map[string]any)
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, nil, nil, fmt.Errorf("JSON 对象键错误")
		}
		var val interface{}
		if err := dec.Decode(&val); err != nil {
			return nil, nil, nil, err
		}
		if _, exists := states[key]; !exists {
			order = append(order, key)
		}
		updateTypeState(states, key, inferJSONValueType(val))
		if obj != nil {
			obj[key] = val
		}
	}
	return order, states, obj, nil
}

func mergeFieldSets(dstOrder *[]string, dstStates map[string]*typeState, srcOrder []string, srcStates map[string]*typeState) {
	for _, name := range srcOrder {
		if _, exists := dstStates[name]; !exists {
			*dstOrder = append(*dstOrder, name)
		}
	}
	for name, state := range srcStates {
		if state != nil {
			updateTypeState(dstStates, name, state.typeName)
		}
	}
}

// decodeJSONArray 遍历顶层数组，汇总字段集合并留下前 PreviewRows 个对象元素，
// 供调用方在字段顺序确定后回填预览。
func decodeJSONArray(dec *json.Decoder, withPreview bool) ([]map[string]any, []string, map[string]*typeState, int64, error) {
	order := make([]string, 0)
	states := map[string]*typeState{}
	rows := int64(0)
	samples := make([]map[string]any, 0, PreviewRows)
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, nil, 0, err
		}
		rows++
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		nested := json.NewDecoder(bytes.NewReader(raw))
		nested.UseNumber()
		tok, err := nested.Token()
		if err != nil {
			return nil, nil, nil, 0, err
		}
		if delim, ok := tok.(json.Delim); !ok || delim != '{' {
			continue
		}
		srcOrder, srcStates, obj, err := decodeJSONObject(nested, withPreview && len(samples) < PreviewRows)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		if _, err := nested.Token(); err != nil {
			return nil, nil, nil, 0, err
		}
		if obj != nil {
			samples = append(samples, obj)
		}
		mergeFieldSets(&order, states, srcOrder, srcStates)
	}
	return samples, order, states, rows, nil
}

func describeParquet(path string, n *Node) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fr, err := goparquet.NewFileReader(f)
	if err != nil {
		return err
	}
	cols := fr.Columns()
	fields := make([]Field, 0, len(cols))
	for _, col := range cols {
		fields = append(fields, Field{Name: col.FlatName(), Type: parquetColumnType(col)})
	}
	rows := fr.NumRows()
	n.Rows = &rows
	n.Fields = fields
	return nil
}

func parquetColumnType(col *goparquet.Column) string {
	elem := col.Element()
	if elem != nil && elem.GetLogicalType() != nil {
		lt := elem.GetLogicalType()
		switch {
		case lt.IsSetSTRING():
			return "str"
		case lt.IsSetDATE():
			return "date"
		case lt.IsSetTIMESTAMP():
			return "datetime"
		case lt.IsSetTIME():
			return "datetime"
		case lt.IsSetLIST():
			return "list"
		case lt.IsSetMAP():
			return "object"
		}
	}
	if elem != nil {
		if elem.IsSetConvertedType() {
			switch elem.GetConvertedType().String() {
			case "UTF8", "ENUM", "JSON", "BSON":
				return "str"
			case "LIST":
				return "list"
			case "MAP":
				return "object"
			}
		}
		switch elem.GetType().String() {
		case "INT32", "INT64":
			return "int"
		case "INT96":
			return "datetime"
		case "FLOAT", "DOUBLE":
			return "float"
		case "BOOLEAN":
			return "bool"
		case "BYTE_ARRAY", "FIXED_LEN_BYTE_ARRAY":
			if elem.IsSetLogicalType() && elem.GetLogicalType().IsSetSTRING() {
				return "str"
			}
			return "str"
		}
	}
	return "str"
}

// ---------------------------------------------------------------------------
// 结构化文件解析（schema + 数据量）
// ---------------------------------------------------------------------------

// previewCell 截断过长的单元格值；非字符串值原样保留。
func previewCell(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	r := []rune(s)
	if len(r) <= previewCellRunes {
		return s
	}
	return string(r[:previewCellRunes]) + "…"
}

// buildPreviewRow 把一行单元格整理成与列定义按位置对齐的预览行：不足补空串，
// 超出丢弃，过长截断。预览行不带列名，全靠位置对齐，所以长度必须恒等于列数。
func buildPreviewRow(cells []any, width int) []any {
	row := make([]any, width)
	for i := 0; i < width; i++ {
		if i < len(cells) {
			row[i] = previewCell(cells[i])
		} else {
			row[i] = ""
		}
	}
	return row
}

// buildObjectPreview 按字段顺序把若干行对象摊平成预览行。
// JSON 对象的键顺序在解码后已丢失，所以字段顺序必须在解析完成后回填。
func buildObjectPreview(objs []map[string]any, fields []Field) [][]any {
	if len(fields) == 0 {
		return nil
	}
	out := make([][]any, 0, len(objs))
	for _, obj := range objs {
		cells := make([]any, len(fields))
		for i, f := range fields {
			cells[i] = jsonCell(obj[f.Name])
		}
		out = append(out, buildPreviewRow(cells, len(fields)))
	}
	return out
}

// jsonCell 把嵌套的 JSON 值压成可放进预览单元格的标量。
func jsonCell(v any) any {
	switch v.(type) {
	case map[string]any, []any:
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return string(b)
	default:
		return v
	}
}

// describeFile 解析单个结构化文件，返回要写进节点的计量信息。
// 任何 panic/错误都兜底为 Warning，不中断整体扫描。
func describeFile(path, format string, size int64, n *Node, withPreview bool, warn func(string)) {
	defer func() {
		if r := recover(); r != nil {
			n.Warning = fmt.Sprintf("解析异常: %v", r)
		}
	}()

	var err error
	switch format {
	case "csv":
		err = describeCSV(path, n, withPreview)
	case "json":
		err = describeJSON(path, n, withPreview)
	case "jsonl":
		err = describeJSONL(path, n, withPreview)
	case "xlsx":
		err = describeXLSX(path, n, withPreview)
	case "sqlite":
		err = describeSQLite(path, n, withPreview)
	case "parquet":
		// 这里只读元数据（列定义与行数），没有行读取路径，因此不产生预览。
		err = describeParquet(path, n)
	default:
		return // 非结构化格式不解析
	}
	if err != nil {
		n.Warning = "解析失败: " + err.Error()
	}
}

// describeCSV 流式统计行数并按列值推断类型，字段顺序保留表头顺序。
func describeCSV(path string, n *Node, withPreview bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	br := bufio.NewReader(io.LimitReader(f, sniffSize))
	sniff, _ := br.ReadString('\n')
	_, _ = f.Seek(0, io.SeekStart)
	runeCounts := map[rune]int{',': 0, ';': 0, '\t': 0}
	for _, r := range sniff {
		if _, ok := runeCounts[r]; ok {
			runeCounts[r]++
		}
	}
	comma := rune(',')
	best := -1
	for r, c := range runeCounts {
		if c > best {
			best = c
			comma = r
		}
	}
	if best <= 0 {
		return countPlainLines(path, n)
	}

	cr := csv.NewReader(f)
	cr.Comma = comma
	cr.FieldsPerRecord = -1
	var header []string
	states := map[string]*typeState{}
	ordered := make([]Field, 0)
	rows := int64(0)
	// 前 PreviewRows 行顺手留下：整表本来就要读一遍，预览不额外增加扫描。
	preview := make([][]any, 0, PreviewRows)
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			if rows == 0 && header == nil {
				return err
			}
			continue
		}
		if header == nil {
			header = append([]string(nil), rec...)
			ordered = make([]Field, len(header))
			for i, name := range header {
				ordered[i].Name = strings.TrimSpace(name)
			}
			continue
		}
		rows++
		if withPreview && len(preview) < PreviewRows {
			cells := make([]any, len(rec))
			for i, v := range rec {
				cells[i] = v
			}
			preview = append(preview, buildPreviewRow(cells, len(header)))
		}
		for i, name := range header {
			if i >= len(rec) {
				continue
			}
			value := strings.TrimSpace(rec[i])
			if value == "" {
				continue
			}
			updateTypeState(states, name, inferTextType(value))
		}
	}
	for i := range ordered {
		ordered[i].Type = finalType(states, ordered[i].Name)
	}
	n.Rows = &rows
	n.Fields = ordered
	if len(ordered) > 0 && len(preview) > 0 {
		n.Preview = preview
	}
	return nil
}

// countPlainLines 无分隔符文本按行计数
func countPlainLines(path string, n *Node) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	rows := int64(0)
	for {
		_, err := br.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		rows++
	}
	n.Rows = &rows
	return nil
}

// describeJSON 全量解析单值 JSON（对象或数组），字段顺序按源顺序保留。
func describeJSON(path string, n *Node, withPreview bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return fmt.Errorf("非对象/数组 JSON")
	}
	switch delim {
	case '{':
		fields, states, _, err := decodeJSONObject(dec, false)
		if err != nil {
			return err
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
		n.Rows = int64Ptr(1)
		n.IsObject = true
		n.Fields = finalizeFields(fields, states)
		return nil
	case '[':
		samples, fields, states, rows, err := decodeJSONArray(dec, withPreview)
		if err != nil {
			return err
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
		n.Rows = &rows
		if len(fields) > 0 {
			n.Fields = finalizeFields(fields, states)
			n.Preview = buildObjectPreview(samples, n.Fields)
		}
		return nil
	default:
		return fmt.Errorf("非对象/数组 JSON")
	}
}

// describeJSONL 逐行流式解析 JSON Lines，字段顺序按首次出现顺序保留。
func describeJSONL(path string, n *Node, withPreview bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	order := make([]string, 0)
	states := map[string]*typeState{}
	docs := int64(0)
	// 前 PreviewRows 行的对象在解析时顺手留下，等字段顺序最终确定后再摊平成预览行。
	samples := make([]map[string]any, 0, PreviewRows)
	for {
		s, err := br.ReadString('\n')
		s = strings.TrimSpace(strings.TrimRight(s, "\r\n"))
		if s != "" {
			docs++
			nested := json.NewDecoder(strings.NewReader(s))
			nested.UseNumber()
			tok, tokErr := nested.Token()
			if tokErr == nil {
				if delim, ok := tok.(json.Delim); ok && delim == '{' {
					srcOrder, srcStates, obj, decErr := decodeJSONObject(nested, withPreview && len(samples) < PreviewRows)
					if decErr != nil {
						return decErr
					}
					if _, endErr := nested.Token(); endErr != nil {
						return endErr
					}
					if obj != nil {
						samples = append(samples, obj)
					}
					mergeFieldSets(&order, states, srcOrder, srcStates)
				} else {
					var any interface{}
					if err := json.Unmarshal([]byte(s), &any); err == nil {
						if len(order) == 0 {
							order = []string{}
						}
					}
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	n.Rows = &docs
	n.Fields = finalizeFields(order, states)
	n.Preview = buildObjectPreview(samples, n.Fields)
	return nil
}

// describeXLSX 用 excelize 只读解析首个工作表，字段顺序按首行顺序保留。
func describeXLSX(path string, n *Node, withPreview bool) error {
	f, err := excelize.OpenFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return fmt.Errorf("无工作表")
	}
	it, err := f.Rows(sheets[0])
	if err != nil {
		return err
	}
	defer it.Close()
	var header []string
	order := make([]string, 0)
	states := map[string]*typeState{}
	rows := int64(0)
	preview := make([][]any, 0, PreviewRows)
	for it.Next() {
		cells, err := it.Columns()
		if err != nil {
			return err
		}
		if header == nil {
			header = make([]string, len(cells))
			order = make([]string, len(cells))
			for i, c := range cells {
				name := strings.TrimSpace(c)
				header[i] = name
				order[i] = name
			}
			continue
		}
		rows++
		if withPreview && len(preview) < PreviewRows {
			values := make([]any, len(cells))
			for i, c := range cells {
				values[i] = c
			}
			preview = append(preview, buildPreviewRow(values, len(header)))
		}
		for i, name := range header {
			if name == "" || i >= len(cells) {
				continue
			}
			value := strings.TrimSpace(cells[i])
			if value == "" {
				continue
			}
			updateTypeState(states, name, inferTextType(value))
		}
	}
	if err := it.Error(); err != nil {
		return err
	}
	n.Rows = &rows
	n.Fields = finalizeFields(order, states)
	if len(order) > 0 && len(preview) > 0 {
		n.Preview = preview
	}
	return nil
}

// describeSQLite 只读打开 SQLite，列出全部表、列定义与行数
func describeSQLite(path string, n *Node, withPreview bool) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query(
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	infos := make([]TableInfo, 0, len(tables))
	total := int64(0)
	for _, t := range tables {
		var cnt int64
		q := fmt.Sprintf(`SELECT COUNT(*) FROM %q`, t)
		if err := db.QueryRow(q).Scan(&cnt); err != nil {
			return err
		}
		info := TableInfo{Name: t, Rows: cnt}
		// 列定义属于元数据，始终带上：其他格式的 files 字段一直都在，
		// 没有列名的位置化预览行也无从解释。
		columns, err := sqliteColumns(db, t)
		if err != nil {
			return err
		}
		info.Columns = columns
		if withPreview {
			preview, err := sqlitePreviewRows(db, t, len(columns))
			if err != nil {
				return err
			}
			info.Preview = preview
		}
		infos = append(infos, info)
		total += cnt
	}
	if len(infos) == 0 {
		return fmt.Errorf("空库")
	}
	n.Tables = infos
	n.Rows = &total
	return nil
}

// sqliteColumns 读取表的列定义，顺序与 SELECT * 一致。
func sqliteColumns(db *sql.DB, table string) ([]Field, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%q)`, table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	fields := make([]Field, 0)
	for rows.Next() {
		var (
			cid       int
			name      string
			declared  string
			notNull   int
			dfltValue any
			pk        int
		)
		if err := rows.Scan(&cid, &name, &declared, &notNull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		fields = append(fields, Field{Name: name, Type: sqliteColumnType(declared)})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fields, nil
}

// sqlitePreviewRows 读取表的前 PreviewRows 行，值保持驱动返回的原生类型。
func sqlitePreviewRows(db *sql.DB, table string, width int) ([][]any, error) {
	if width == 0 {
		return nil, nil
	}
	rows, err := db.Query(fmt.Sprintf(`SELECT * FROM %q LIMIT %d`, table, PreviewRows))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([][]any, 0, PreviewRows)
	for rows.Next() {
		scanned := make([]any, width)
		targets := make([]any, width)
		for i := range scanned {
			targets[i] = &scanned[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, err
		}
		cells := make([]any, width)
		for i, v := range scanned {
			cells[i] = sqliteCell(v)
		}
		out = append(out, buildPreviewRow(cells, width))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// sqliteCell BLOB 等字节切片转字符串，其余类型原样保留。
func sqliteCell(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

// sqliteColumnType 按 SQLite 的类型亲和性规则把声明类型归一到与其他格式一致的词汇表，
// 否则 fields[].type 在 sqlite 上会是 INTEGER/TEXT，与 csv 的 int/str 对不上。
func sqliteColumnType(declared string) string {
	t := strings.ToUpper(strings.TrimSpace(declared))
	switch {
	case t == "":
		return "str" // BLOB 亲和性
	case strings.Contains(t, "INT"):
		return "int"
	case strings.Contains(t, "CHAR"), strings.Contains(t, "CLOB"), strings.Contains(t, "TEXT"):
		return "str"
	case strings.Contains(t, "BLOB"):
		return "str"
	case strings.Contains(t, "BOOL"):
		return "bool"
	case strings.Contains(t, "DATETIME"), strings.Contains(t, "TIMESTAMP"):
		return "datetime"
	case strings.Contains(t, "DATE"):
		return "date"
	case strings.Contains(t, "TIME"):
		return "datetime"
	case strings.Contains(t, "REAL"), strings.Contains(t, "FLOA"), strings.Contains(t, "DOUB"):
		return "float"
	default:
		// 未识别的声明类型按最保守的猜测处理，不猜成数值。
		return "str"
	}
}

// ---------------------------------------------------------------------------
// 目录扫描与树构建
// ---------------------------------------------------------------------------

type scanner struct {
	root       string
	maxFiles   int
	maxParse   int64 // 单文件解析上限
	preview    bool  // 是否生成表格类文件的预览行
	totalSize  int64
	fileCount  int
	structured int
	byFormat   map[string]*FormatStat
	warnings   []string
}

func (s *scanner) warn(msg string) {
	s.warnings = append(s.warnings, msg)
}

// scan 递归扫描目录，返回以 dirName 为根的树
func (s *scanner) scan(dir string, rel string) (*Node, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	node := &Node{
		Name: filepath.Base(dir),
		Type: "dir",
	}
	type item struct {
		ent   os.DirEntry
		child *Node
	}
	var dirs, files []item

	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		childRel := e.Name()
		if rel != "" {
			childRel = rel + "/" + e.Name()
		}
		if e.IsDir() {
			child, err := s.scan(full, childRel)
			if err != nil {
				s.warn(fmt.Sprintf("目录读取失败 %s: %v", childRel, err))
				continue
			}
			dirs = append(dirs, item{e, child})
		} else {
			info, err := e.Info()
			if err != nil {
				s.warn(fmt.Sprintf("文件信息读取失败 %s: %v", childRel, err))
				continue
			}
			if s.fileCount >= s.maxFiles {
				s.warn(fmt.Sprintf("文件数超过上限 %d，%s 起跳过", s.maxFiles, childRel))
				continue
			}
			child := s.scanFile(full, childRel, info)
			files = append(files, item{e, child})
		}
	}

	sort.Slice(dirs, func(i, j int) bool { return dirs[i].ent.Name() < dirs[j].ent.Name() })
	sort.Slice(files, func(i, j int) bool { return files[i].ent.Name() < files[j].ent.Name() })

	for _, it := range dirs {
		node.Children = append(node.Children, it.child)
	}
	for _, it := range files {
		node.Children = append(node.Children, it.child)
	}
	node.FileCount = s.dirCount(node)
	return node, nil
}

// dirCount 递归统计目录节点下的文件总数
func (s *scanner) dirCount(n *Node) int {
	c := 0
	for _, ch := range n.Children {
		if ch.Type == "dir" {
			c += ch.FileCount
		} else {
			c++
		}
	}
	return c
}

// scanFile 扫描单个文件：魔数探测 + 结构化解析
func (s *scanner) scanFile(full, rel string, info os.FileInfo) *Node {
	n := &Node{
		Name: info.Name(),
		Type: "file",
		Size: info.Size(),
	}
	s.fileCount++
	s.totalSize += info.Size()

	if info.Size() == 0 {
		n.Format = classifyByExt(full)
		n.Warning = "空文件"
		return n
	}

	// 魔数探测
	head := make([]byte, headSize)
	f, err := os.Open(full)
	if err != nil {
		n.Format = "application/octet-stream"
		n.Warning = "无法读取"
		return n
	}
	nr, _ := io.ReadFull(f, head)
	head = head[:nr]
	f.Close()

	n.Format = detectFormat(head, full)

	// 结构化解析（带单文件大小上限）
	if info.Size() <= s.maxParse {
		describeFile(full, n.Format, info.Size(), n, s.preview, s.warn)
	} else {
		n.Warning = fmt.Sprintf("超过单文件解析上限 %s，仅识别格式", humanSize(s.maxParse))
	}

	// 统计
	st, ok := s.byFormat[n.Format]
	if !ok {
		st = &FormatStat{Format: n.Format}
		s.byFormat[n.Format] = st
	}
	st.Count++
	st.SizeSum += info.Size()
	if len(n.Fields) > 0 || len(n.Tables) > 0 {
		s.structured++
	}
	if n.Warning != "" {
		s.warn(fmt.Sprintf("%s: %s", rel, n.Warning))
	}
	return n
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

func humanSize(n int64) string {
	const unit = 1024.0
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
