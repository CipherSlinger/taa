// dstree — 目录树解析工具（多模态数据集 → JSON）
// ================================================================
// 扫描一个数据集目录，按魔数（magic bytes）识别文件格式（不信扩展名），
// 对结构化文件就地解析 schema 与数据量，输出一棵带标注的目录树 JSON。
//
// 覆盖格式：CSV / TSV / XLSX / JSON / JSONL / SQLite / Parquet(仅识别)
//           PNG / JPEG / GIF / WEBP / PDF / ZIP / GZIP / 纯文本
//
// 设计约束（面向 TEE 侧部署）：
//   - CSV/JSONL 逐行流式读取，内存占用与文件大小无关
//   - 单文件解析上限（默认 128MB）与文件总数上限（默认 100000），防 zip bomb / 恶意超大输入
//   - 单个文件解析失败只降级为警告标注，不中断整棵树
//
// 用法：
//   go build -o dstree .
//   ./dstree -root /path/to/dataset -o tree.json
//   ./dstree -root /path/to/dataset            # 输出到 stdout
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	goparquet "github.com/fraugster/parquet-go"
	"github.com/xuri/excelize/v2"
	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，无 CGO 依赖
)

const (
	toolVersion = "1.0.0"
	headSize    = 512   // 魔数探测读取的头部字节数
	sniffSize   = 1 << 20 // 文本嗅探上限 1MB
)

// TableInfo SQLite 内单张表的信息
type TableInfo struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

// Field 描述结构化文件里的一个字段
type Field struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Node 目录树节点：目录与文件统一结构，文件无 children
type Node struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"` // "dir" | "file"

	// 文件属性
	Format   string      `json:"fmt,omitempty"` // 魔数探测出的格式标签
	Size     int64       `json:"size,omitempty"`
	Rows     *int64      `json:"rows,omitempty"`    // 数值型行/条数（前端可排序）
	IsObject bool        `json:"isObject,omitempty"` // JSON 是否为对象
	Fields   []Field     `json:"fields,omitempty"`   // schema：顶层字段/表头
	Tables   []TableInfo `json:"tables,omitempty"`    // SQLite 表级明细
	Warning  string      `json:"warning,omitempty"`  // 解析失败/截断等警告

	// 目录属性
	FileCount int     `json:"file_count,omitempty"` // 目录下（递归）文件总数
	Children  []*Node `json:"children,omitempty"`
}

// FormatStat 格式分布统计
type FormatStat struct {
	Format  string `json:"format"`
	Count   int    `json:"count"`
	SizeSum int64  `json:"size_sum"`
}

// Report 最终 JSON 报告
type Report struct {
	Version      string       `json:"version"`
	GeneratedAt  string       `json:"generated_at"`
	TotalFiles   int          `json:"total_files"`
	TotalSize    int64        `json:"total_size"`
	TotalSizeH   string       `json:"total_size_h"`
	Structured   int          `json:"structured_files"` // 成功解析出 schema/行数的文件数
	Warnings     []string     `json:"warnings,omitempty"`
	ByFormat     []FormatStat `json:"by_format"`
	Tree         *Node        `json:"tree"`
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
	s := string(bytes.Runes(head))
	for _, r := range s {
		if r == 0xFFFD { // 无效 UTF-8 替换符
			return false
		}
	}
	return true
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

func inferAnyType(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return inferTextType(x)
	case json.Number:
		return inferNumberType(x.String())
	case float32:
		return inferNumberType(strconv.FormatFloat(float64(x), 'f', -1, 32))
	case float64:
		return inferNumberType(strconv.FormatFloat(x, 'f', -1, 64))
	case int:
		return "int"
	case int8, int16, int32, int64:
		return "int"
	case uint, uint8, uint16, uint32, uint64:
		return "int"
	case bool:
		return "bool"
	case time.Time:
		return "datetime"
	case map[string]interface{}:
		return "object"
	case []interface{}:
		return "list"
	case []byte:
		return inferTextType(string(x))
	default:
		return inferTextType(fmt.Sprint(x))
	}
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
	if typ := inferNumberType(s); typ != "str" {
		return typ
	}
	return "str"
}

func decodeJSONObject(dec *json.Decoder) ([]string, map[string]*typeState, error) {
	order := make([]string, 0)
	states := map[string]*typeState{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, nil, fmt.Errorf("JSON 对象键错误")
		}
		var val interface{}
		if err := dec.Decode(&val); err != nil {
			return nil, nil, err
		}
		if _, exists := states[key]; !exists {
			order = append(order, key)
		}
		updateTypeState(states, key, inferJSONValueType(val))
	}
	return order, states, nil
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

func decodeJSONArray(dec *json.Decoder) ([]string, map[string]*typeState, int64, error) {
	order := make([]string, 0)
	states := map[string]*typeState{}
	rows := int64(0)
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, 0, err
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
			return nil, nil, 0, err
		}
		delim, ok := tok.(json.Delim)
		if !ok || delim != '{' {
			continue
		}
		srcOrder, srcStates, err := decodeJSONObject(nested)
		if err != nil {
			return nil, nil, 0, err
		}
		if _, err := nested.Token(); err != nil {
			return nil, nil, 0, err
		}
		mergeFieldSets(&order, states, srcOrder, srcStates)
	}
	return order, states, rows, nil
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

// describeFile 解析单个结构化文件，返回要写进节点的计量信息。
// 任何 panic/错误都兜底为 Warning，不中断整体扫描。
func describeFile(path, format string, size int64, n *Node, warn func(string)) {
	defer func() {
		if r := recover(); r != nil {
			n.Warning = fmt.Sprintf("解析异常: %v", r)
		}
	}()

	var err error
	switch format {
	case "csv":
		err = describeCSV(path, n)
	case "json":
		err = describeJSON(path, n)
	case "jsonl":
		err = describeJSONL(path, n)
	case "xlsx":
		err = describeXLSX(path, n)
	case "sqlite":
		err = describeSQLite(path, n)
	case "parquet":
		err = describeParquet(path, n)
	default:
		return // 非结构化格式不解析
	}
	if err != nil {
		n.Warning = "解析失败: " + err.Error()
	}
}

// describeCSV 流式统计行数并按列值推断类型，字段顺序保留表头顺序。
func describeCSV(path string, n *Node) error {
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
func describeJSON(path string, n *Node) error {
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
		fields, states, err := decodeJSONObject(dec)
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
		fields, states, rows, err := decodeJSONArray(dec)
		if err != nil {
			return err
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
		n.Rows = &rows
		if len(fields) > 0 {
			n.Fields = finalizeFields(fields, states)
		}
		return nil
	default:
		return fmt.Errorf("非对象/数组 JSON")
	}
}

// describeJSONL 逐行流式解析 JSON Lines，字段顺序按首次出现顺序保留。
func describeJSONL(path string, n *Node) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	order := make([]string, 0)
	states := map[string]*typeState{}
	docs := int64(0)
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
					srcOrder, srcStates, decErr := decodeJSONObject(nested)
					if decErr != nil {
						return decErr
					}
					if _, endErr := nested.Token(); endErr != nil {
						return endErr
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
	return nil
}

// describeXLSX 用 excelize 只读解析首个工作表，字段顺序按首行顺序保留。
func describeXLSX(path string, n *Node) error {
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
	return nil
}

// describeSQLite 只读打开 SQLite，列出全部表与行数
func describeSQLite(path string, n *Node) error {
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
		infos = append(infos, TableInfo{Name: t, Rows: cnt})
		total += cnt
	}
	if len(infos) == 0 {
		return fmt.Errorf("空库")
	}
	n.Tables = infos
	n.Rows = &total
	return nil
}

// ---------------------------------------------------------------------------
// 目录扫描与树构建
// ---------------------------------------------------------------------------

type scanner struct {
	root      string
	maxFiles  int
	maxParse  int64 // 单文件解析上限
	totalSize int64
	fileCount int
	structured int
	byFormat  map[string]*FormatStat
	warnings  []string
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
	type item struct{ ent os.DirEntry; child *Node }
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
			c += s.dirCount(ch)
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
		describeFile(full, n.Format, info.Size(), n, s.warn)
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

func main() {
	var (
		root     = flag.String("root", "../models/examples/Retina-DKD/test/", "要扫描的数据集目录")
		out      = flag.String("o", "./Retina-DKD-filetree.json", "输出 JSON 文件路径（缺省输出到 stdout）")
		maxFiles = flag.Int("max-files", 100000, "文件总数上限")
		maxParse = flag.Int64("max-parse-mb", 128, "单文件结构化解析上限（MB）")
	)
	flag.Parse()

	abs, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "路径错误:", err)
		os.Exit(1)
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		fmt.Fprintln(os.Stderr, "不是有效目录:", *root)
		os.Exit(1)
	}

	s := &scanner{
		root:     abs,
		maxFiles: *maxFiles,
		maxParse: *maxParse << 20,
		byFormat: map[string]*FormatStat{},
	}
	tree, err := s.scan(abs, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "扫描失败:", err)
		os.Exit(1)
	}
	tree.Name = filepath.Base(abs)

	// 格式分布排序
	formats := make([]FormatStat, 0, len(s.byFormat))
	for _, v := range s.byFormat {
		formats = append(formats, *v)
	}
	sort.Slice(formats, func(i, j int) bool { return formats[i].Count > formats[j].Count })

	report := Report{
		Version:     toolVersion,
		GeneratedAt:  time.Now().Format(time.RFC3339),
		TotalFiles:   s.fileCount,
		TotalSize:    s.totalSize,
		TotalSizeH:   humanSize(s.totalSize),
		Structured:   s.structured,
		Warnings:     s.warnings,
		ByFormat:     formats,
		Tree:         tree,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "JSON 序列化失败:", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if *out != "" {
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "写入失败:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "已写入 %s：%d 个文件，%s，结构化文件 %d 个\n",
			*out, report.TotalFiles, report.TotalSizeH, report.Structured)
	} else {
		os.Stdout.Write(data)
	}
}
