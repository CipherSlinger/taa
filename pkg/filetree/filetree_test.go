package filetree

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	goparquet "github.com/fraugster/parquet-go"
	"github.com/fraugster/parquet-go/parquet"
	"github.com/fraugster/parquet-go/parquetschema"
	"github.com/xuri/excelize/v2"
	_ "modernc.org/sqlite"
)

func TestScanMatchesExampleContract(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "docs", "README.md"), []byte("# readme\n"))
	mustWriteFile(t, filepath.Join(root, "docs", "schema_notes.txt"), []byte("alpha\nbeta\n"))
	mustWriteFile(t, filepath.Join(root, "metadata.yaml"), []byte("version: 1\nname: demo\n"))
	mustWriteFile(t, filepath.Join(root, "assets", "placeholder.csv"), nil)
	mustWriteFile(t, filepath.Join(root, "warehouse", "empty_log.db"), nil)

	tree := scanTree(t, root)
	readme := mustFindNode(t, tree, "README.md")
	if readme.Format != "md" {
		t.Fatalf("README.md fmt = %q, want %q", readme.Format, "md")
	}
	if got := rawNodeJSON(t, readme); strings.Contains(got, "size_h") {
		t.Fatalf("README.md JSON unexpectedly contains size_h: %s", got)
	}

	plain := mustFindNode(t, tree, "schema_notes.txt")
	if plain.Format != "txt" {
		t.Fatalf("schema_notes.txt fmt = %q, want %q", plain.Format, "txt")
	}

	yaml := mustFindNode(t, tree, "metadata.yaml")
	if yaml.Format != "yaml" {
		t.Fatalf("metadata.yaml fmt = %q, want %q", yaml.Format, "yaml")
	}

	emptyCSV := mustFindNode(t, tree, "placeholder.csv")
	if emptyCSV.Format != "csv" {
		t.Fatalf("placeholder.csv fmt = %q, want %q", emptyCSV.Format, "csv")
	}
	if emptyCSV.Warning != "空文件" {
		t.Fatalf("placeholder.csv warning = %q, want %q", emptyCSV.Warning, "空文件")
	}

	emptyDB := mustFindNode(t, tree, "empty_log.db")
	if emptyDB.Format != "sqlite" {
		t.Fatalf("empty_log.db fmt = %q, want %q", emptyDB.Format, "sqlite")
	}
	if emptyDB.Warning != "空文件" {
		t.Fatalf("empty_log.db warning = %q, want %q", emptyDB.Warning, "空文件")
	}
}

func TestScanInfersTypedFieldsInSourceOrder(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "raw", "users.csv"), []byte(strings.Join([]string{
		"user_id,price,active,created_at,birthday,name",
		"1,12.5,true,2026-09-08T10:00:00Z,2026-09-08,Alice",
		"2,3.25,false,2026-09-09T11:30:00Z,2026-09-09,Bob",
		"3,,true,2026-09-10T12:00:00Z,2026-09-10,Carol",
	}, "\n")+"\n"))

	mustWriteFile(t, filepath.Join(root, "raw", "clickstream.jsonl"), []byte(strings.Join([]string{
		`{"event_id":"e1","user_id":1,"event_type":"click","timestamp":"2026-09-08T10:11:12Z","page_url":"https://example.test/a","referrer":"https://example.test","device":"mobile","properties":{"x":1,"y":"z"},"tags":["a","b"]}`,
		`{"event_id":"e2","user_id":2,"event_type":"view","timestamp":"2026-09-08T10:12:12Z","page_url":"https://example.test/b","referrer":"https://example.test/a","device":"desktop","properties":{"x":2},"tags":[]}`,
	}, "\n")+"\n"))

	mustWriteFile(t, filepath.Join(root, "raw", "config.json"), []byte(`{"version":"1.0","schema_version":2,"ingestion_pipeline":{"name":"demo"},"quality_rules":["non_empty"],"schedule":"0 0 * * *"}`))

	mustWriteXLSXFile(t, filepath.Join(root, "raw", "orders.xlsx"), [][]any{
		{"order_id", "amount", "paid", "order_date", "ordered_at", "customer"},
		{"o1", 12.5, true, "2026-09-08", "2026-09-08T10:00:00Z", "Alice"},
		{"o2", 3, false, "2026-09-09", "2026-09-09T11:00:00Z", "Bob"},
	})

	tree := scanTree(t, root)

	assertFields(t, mustFindNode(t, tree, "users.csv"), []Field{
		{Name: "user_id", Type: "int"},
		{Name: "price", Type: "float"},
		{Name: "active", Type: "bool"},
		{Name: "created_at", Type: "datetime"},
		{Name: "birthday", Type: "date"},
		{Name: "name", Type: "str"},
	})

	assertFields(t, mustFindNode(t, tree, "clickstream.jsonl"), []Field{
		{Name: "event_id", Type: "str"},
		{Name: "user_id", Type: "int"},
		{Name: "event_type", Type: "str"},
		{Name: "timestamp", Type: "datetime"},
		{Name: "page_url", Type: "str"},
		{Name: "referrer", Type: "str"},
		{Name: "device", Type: "str"},
		{Name: "properties", Type: "object"},
		{Name: "tags", Type: "list"},
	})

	assertFields(t, mustFindNode(t, tree, "config.json"), []Field{
		{Name: "version", Type: "str"},
		{Name: "schema_version", Type: "int"},
		{Name: "ingestion_pipeline", Type: "object"},
		{Name: "quality_rules", Type: "list"},
		{Name: "schedule", Type: "str"},
	})

	assertFields(t, mustFindNode(t, tree, "orders.xlsx"), []Field{
		{Name: "order_id", Type: "str"},
		{Name: "amount", Type: "float"},
		{Name: "paid", Type: "bool"},
		{Name: "order_date", Type: "date"},
		{Name: "ordered_at", Type: "datetime"},
		{Name: "customer", Type: "str"},
	})
}

func TestScanReadsSQLiteAndParquetDetails(t *testing.T) {
	root := t.TempDir()
	mustWriteSQLiteFile(t, filepath.Join(root, "warehouse", "analytics.db"))
	mustWriteParquetFile(t, filepath.Join(root, "processed", "user_profiles.parquet"))

	tree := scanTree(t, root)

	sqliteNode := mustFindNode(t, tree, "analytics.db")
	if sqliteNode.Format != "sqlite" {
		t.Fatalf("analytics.db fmt = %q, want %q", sqliteNode.Format, "sqlite")
	}
	if sqliteNode.Rows == nil || *sqliteNode.Rows != 9 {
		t.Fatalf("analytics.db rows = %v, want 9", sqliteNode.Rows)
	}
	assertTables(t, sqliteNode, []TableInfo{
		{Name: "dim_users", Rows: 4},
		{Name: "fct_orders", Rows: 5},
	})

	parquetNode := mustFindNode(t, tree, "user_profiles.parquet")
	if parquetNode.Format != "parquet" {
		t.Fatalf("user_profiles.parquet fmt = %q, want %q", parquetNode.Format, "parquet")
	}
	if parquetNode.Rows == nil || *parquetNode.Rows != 2 {
		t.Fatalf("user_profiles.parquet rows = %v, want 2", parquetNode.Rows)
	}
	assertFields(t, parquetNode, []Field{
		{Name: "user_id", Type: "int"},
		{Name: "lifetime_value", Type: "float"},
		{Name: "segment", Type: "str"},
	})
	// parquet 只读元数据，没有行读取路径，因此没有预览
	if len(parquetNode.Preview) != 0 {
		t.Fatalf("user_profiles.parquet preview = %#v, want none", parquetNode.Preview)
	}
}

func TestPreviewKeepsFirstRowsAlignedToFields(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "users.csv"), []byte(strings.Join([]string{
		"user_id,name,note",
		"1,user1,n1",
		"2,user2,n2",
		"3,user3",
		"4,user4,n4",
		"5,user5,n5",
		"6,user6,n6",
		"7,user7,n7",
	}, "\n")+"\n"))

	node := mustFindNode(t, scanTree(t, root), "users.csv")
	if node.Rows == nil || *node.Rows != 7 {
		t.Fatalf("users.csv rows = %v, want 7", node.Rows)
	}
	// 只留前 5 行；第 3 行缺列，必须补空串才能保持位置对齐
	assertPreview(t, node.Name, node.Preview,
		`[["1","user1","n1"],["2","user2","n2"],["3","user3",""],["4","user4","n4"],["5","user5","n5"]]`)
}

func TestPreviewCoversJSONLJSONArrayAndXLSX(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "events.jsonl"), []byte(strings.Join([]string{
		`{"a":1,"b":"x"}`,
		`{"a":2,"b":"y"}`,
		`{"b":"z","a":3}`,
	}, "\n")+"\n"))
	mustWriteFile(t, filepath.Join(root, "list.json"), []byte(`[{"a":1,"b":"x"},{"a":2,"b":"y"}]`))
	mustWriteFile(t, filepath.Join(root, "single.json"), []byte(`{"a":1}`))
	mustWriteXLSXFile(t, filepath.Join(root, "orders.xlsx"), [][]any{
		{"id", "amount"},
		{"o1", "1.5"},
		{"o2", "2.5"},
	})

	tree := scanTree(t, root)

	// 字段顺序在源码里是首次出现的顺序，所以第三行虽写成 b,a，预览仍按 a,b 排列
	assertPreview(t, "events.jsonl", mustFindNode(t, tree, "events.jsonl").Preview,
		`[[1,"x"],[2,"y"],[3,"z"]]`)
	assertPreview(t, "list.json", mustFindNode(t, tree, "list.json").Preview,
		`[[1,"x"],[2,"y"]]`)
	assertPreview(t, "orders.xlsx", mustFindNode(t, tree, "orders.xlsx").Preview,
		`[["o1","1.5"],["o2","2.5"]]`)
	// 单值 JSON 对象不是表格，没有预览
	if single := mustFindNode(t, tree, "single.json"); single.Preview != nil {
		t.Fatalf("single.json preview = %#v, want nil", single.Preview)
	}
}

func TestPreviewReadsSQLiteColumnsAndRows(t *testing.T) {
	root := t.TempDir()
	mustWriteSQLiteFile(t, filepath.Join(root, "analytics.db"))

	node := mustFindNode(t, scanTree(t, root), "analytics.db")
	if len(node.Tables) != 2 {
		t.Fatalf("tables len = %d, want 2", len(node.Tables))
	}

	assertFieldList(t, "dim_users", node.Tables[0].Columns, []Field{
		{Name: "id", Type: "int"},
		{Name: "name", Type: "str"},
	})
	assertPreview(t, "dim_users", node.Tables[0].Preview,
		`[[1,"a"],[2,"b"],[3,"c"],[4,"d"]]`)

	assertFieldList(t, "fct_orders", node.Tables[1].Columns, []Field{
		{Name: "id", Type: "int"},
		{Name: "amount", Type: "float"},
	})
	assertPreview(t, "fct_orders", node.Tables[1].Preview,
		`[[1,1.5],[2,2.5],[3,3.5],[4,4.5],[5,5.5]]`)
}

func TestPreviewTruncatesLongCells(t *testing.T) {
	root := t.TempDir()
	long := strings.Repeat("x", 200)
	mustWriteFile(t, filepath.Join(root, "wide.csv"), []byte("a,b\n"+long+",short\n"))

	node := mustFindNode(t, scanTree(t, root), "wide.csv")
	if len(node.Preview) != 1 || len(node.Preview[0]) != 2 {
		t.Fatalf("preview shape = %#v", node.Preview)
	}
	cell, ok := node.Preview[0][0].(string)
	if !ok {
		t.Fatalf("cell type = %T, want string", node.Preview[0][0])
	}
	if want := strings.Repeat("x", previewCellRunes) + "…"; cell != want {
		t.Fatalf("long cell = %q (len %d), want length %d with ellipsis", cell, len([]rune(cell)), previewCellRunes+1)
	}
	if node.Preview[0][1] != "short" {
		t.Fatalf("short cell = %#v, want %q", node.Preview[0][1], "short")
	}
}

func TestPreviewStaysOffUnlessRequested(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "users.csv"), []byte("a,b\n1,2\n"))
	mustWriteSQLiteFile(t, filepath.Join(root, "analytics.db"))

	// 默认关闭：报告类产物会落盘到结果目录并随导出接口外发，
	// 预览等于把真实数据值送进导出产物。
	off, err := BuildReport(root, DefaultOptions())
	if err != nil {
		t.Fatalf("BuildReport with DefaultOptions failed: %v", err)
	}
	assertNoPreview(t, off.Tree)

	on, err := BuildReport(root, Options{IncludePreview: true})
	if err != nil {
		t.Fatalf("BuildReport with IncludePreview failed: %v", err)
	}
	assertPreview(t, "users.csv", mustFindNode(t, on.Tree, "users.csv").Preview, `[["1","2"]]`)

	// 列定义属于元数据而非数据值，两种模式下都要有
	for _, rep := range []*Report{off, on} {
		db := mustFindNode(t, rep.Tree, "analytics.db")
		if len(db.Tables) == 0 || len(db.Tables[0].Columns) == 0 {
			t.Fatalf("analytics.db columns missing: %#v", db.Tables)
		}
	}
}

func scanTree(t *testing.T, root string) *Node {
	t.Helper()
	return scanTreeWithPreview(t, root, true)
}

func scanTreeWithPreview(t *testing.T, root string, preview bool) *Node {
	t.Helper()
	s := &scanner{
		root:     root,
		maxFiles: 100000,
		maxParse: 128 << 20,
		preview:  preview,
		byFormat: map[string]*FormatStat{},
	}
	tree, err := s.scan(root, "")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	tree.Name = filepath.Base(root)
	return tree
}

func mustFindNode(t *testing.T, n *Node, name string) *Node {
	t.Helper()
	if n == nil {
		t.Fatalf("node %q not found: tree is nil", name)
	}
	if n.Name == name {
		return n
	}
	for _, ch := range n.Children {
		if got := mustFindNodeOptional(ch, name); got != nil {
			return got
		}
	}
	t.Fatalf("node %q not found", name)
	return nil
}

func mustFindNodeOptional(n *Node, name string) *Node {
	if n == nil {
		return nil
	}
	if n.Name == name {
		return n
	}
	for _, ch := range n.Children {
		if got := mustFindNodeOptional(ch, name); got != nil {
			return got
		}
	}
	return nil
}

func assertFields(t *testing.T, n *Node, want []Field) {
	t.Helper()
	if n == nil {
		t.Fatal("node is nil")
	}
	assertFieldList(t, n.Name, n.Fields, want)
}

func assertFieldList(t *testing.T, label string, got, want []Field) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s fields len = %d, want %d", label, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s field %d = %#v, want %#v", label, i, got[i], want[i])
		}
	}
}

// assertTables 只比对表名与行数，列定义与预览由专门的用例断言。
func assertTables(t *testing.T, n *Node, want []TableInfo) {
	t.Helper()
	if len(n.Tables) != len(want) {
		t.Fatalf("%s tables len = %d, want %d", n.Name, len(n.Tables), len(want))
	}
	for i := range want {
		if n.Tables[i].Name != want[i].Name || n.Tables[i].Rows != want[i].Rows {
			t.Fatalf("%s table %d = (%s, %d), want (%s, %d)",
				n.Name, i, n.Tables[i].Name, n.Tables[i].Rows, want[i].Name, want[i].Rows)
		}
	}
}

// assertPreview 以 JSON 形态比对预览，规避驱动返回值在 int64/float64 上的差异。
func assertPreview(t *testing.T, label string, got [][]any, want string) {
	t.Helper()
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("%s marshal preview failed: %v", label, err)
	}
	if string(data) != want {
		t.Fatalf("%s preview = %s, want %s", label, data, want)
	}
}

// assertNoPreview 递归确认整棵树都没有携带预览行。
func assertNoPreview(t *testing.T, n *Node) {
	t.Helper()
	if len(n.Preview) != 0 {
		t.Fatalf("%s unexpectedly carries a preview: %#v", n.Name, n.Preview)
	}
	for _, tb := range n.Tables {
		if len(tb.Preview) != 0 {
			t.Fatalf("%s table %s unexpectedly carries a preview: %#v", n.Name, tb.Name, tb.Preview)
		}
	}
	for _, ch := range n.Children {
		assertNoPreview(t, ch)
	}
}

func rawNodeJSON(t *testing.T, n *Node) string {
	t.Helper()
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal node failed: %v", err)
	}
	return string(data)
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s failed: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s failed: %v", path, err)
	}
}

func mustWriteXLSXFile(t *testing.T, path string, rows [][]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s failed: %v", path, err)
	}
	f := excelize.NewFile()
	sheet := f.GetSheetName(0)
	for i, row := range rows {
		for j, val := range row {
			cell, err := excelize.CoordinatesToCellName(j+1, i+1)
			if err != nil {
				t.Fatalf("cell name failed: %v", err)
			}
			if err := f.SetCellValue(sheet, cell, val); err != nil {
				t.Fatalf("set cell %s failed: %v", cell, err)
			}
		}
	}
	if err := f.SaveAs(path); err != nil {
		t.Fatalf("save xlsx failed: %v", err)
	}
}

func mustWriteSQLiteFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s failed: %v", path, err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE dim_users (id INTEGER PRIMARY KEY, name TEXT);`,
		`INSERT INTO dim_users(name) VALUES ('a'), ('b'), ('c'), ('d');`,
		`CREATE TABLE fct_orders (id INTEGER PRIMARY KEY, amount REAL);`,
		`INSERT INTO fct_orders(amount) VALUES (1.5), (2.5), (3.5), (4.5), (5.5);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec sqlite stmt failed: %v", err)
		}
	}
}

func mustWriteParquetFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s failed: %v", path, err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create parquet failed: %v", err)
	}
	defer f.Close()
	schemaDef, err := parquetschema.ParseSchemaDefinition(`message test {
		required int64 user_id;
		required double lifetime_value;
		required binary segment (STRING);
	}`)
	if err != nil {
		t.Fatalf("parse parquet schema failed: %v", err)
	}
	fw := goparquet.NewFileWriter(f,
		goparquet.WithSchemaDefinition(schemaDef),
		goparquet.WithCompressionCodec(parquet.CompressionCodec_SNAPPY),
		goparquet.WithCreator("test"),
	)
	rows := []map[string]any{
		{"user_id": int64(1), "lifetime_value": float64(10.5), "segment": []byte("A")},
		{"user_id": int64(2), "lifetime_value": float64(20.25), "segment": []byte("B")},
	}
	for _, row := range rows {
		if err := fw.AddData(row); err != nil {
			t.Fatalf("add parquet row failed: %v", err)
		}
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("close parquet failed: %v", err)
	}
}

func TestReportChecksum(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "a.txt"), []byte("hello"))
	mustWriteFile(t, filepath.Join(root, "b.txt"), []byte("world"))

	// 1. 默认目录遍历计算 SM3
	repDefault, err := BuildReport(root, DefaultOptions())
	if err != nil {
		t.Fatalf("BuildReport failed: %v", err)
	}
	if repDefault.Checksum == nil {
		t.Fatal("repDefault.Checksum is nil")
	}
	if repDefault.Checksum.Algorithm != "sm3" {
		t.Fatalf("algorithm = %q, want %q", repDefault.Checksum.Algorithm, "sm3")
	}
	if repDefault.Checksum.Value == "" {
		t.Fatal("checksum value is empty")
	}
	if repDefault.Checksum.Size != 10 {
		t.Fatalf("checksum size = %d, want 10", repDefault.Checksum.Size)
	}

	// 2. 指定 ArchivePath
	archiveFile := filepath.Join(t.TempDir(), "data.tar.gz")
	mustWriteFile(t, archiveFile, []byte("fake-tar-gz-content"))
	repArchive, err := BuildReport(root, Options{
		ArchivePath: archiveFile,
	})
	if err != nil {
		t.Fatalf("BuildReport with archive failed: %v", err)
	}
	if repArchive.Checksum == nil {
		t.Fatal("repArchive.Checksum is nil")
	}
	if repArchive.Checksum.Algorithm != "sm3" {
		t.Fatalf("algorithm = %q, want %q", repArchive.Checksum.Algorithm, "sm3")
	}
	if repArchive.Checksum.Size != int64(len("fake-tar-gz-content")) {
		t.Fatalf("archive checksum size = %d, want %d", repArchive.Checksum.Size, len("fake-tar-gz-content"))
	}

	// 3. 显式传入 Checksum
	repExplicit, err := BuildReport(root, Options{
		Checksum: &ChecksumInfo{
			Algorithm: "sm3",
			Value:     "custom-sm3-hash",
			Size:      12345,
		},
	})
	if err != nil {
		t.Fatalf("BuildReport with explicit checksum failed: %v", err)
	}
	if repExplicit.Checksum == nil || repExplicit.Checksum.Value != "custom-sm3-hash" {
		t.Fatalf("explicit checksum = %#v", repExplicit.Checksum)
	}

	// 4. SkipChecksum：不计算校验和，但目录结构照常扫描
	repSkipped, err := BuildReport(root, Options{SkipChecksum: true})
	if err != nil {
		t.Fatalf("BuildReport with SkipChecksum failed: %v", err)
	}
	if repSkipped.Checksum != nil {
		t.Fatalf("SkipChecksum should leave Checksum nil, got %#v", repSkipped.Checksum)
	}
	if repSkipped.TotalFiles != 2 || repSkipped.Tree == nil {
		t.Fatalf("SkipChecksum must not skip the scan: files=%d tree=%v", repSkipped.TotalFiles, repSkipped.Tree)
	}
}
