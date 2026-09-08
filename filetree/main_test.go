package main

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
	_ "modernc.org/sqlite"
	"github.com/xuri/excelize/v2"
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
}

func scanTree(t *testing.T, root string) *Node {
	t.Helper()
	s := &scanner{
		root:     root,
		maxFiles: 100000,
		maxParse: 128 << 20,
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
	if len(n.Fields) != len(want) {
		t.Fatalf("%s fields len = %d, want %d", n.Name, len(n.Fields), len(want))
	}
	for i := range want {
		if n.Fields[i] != want[i] {
			t.Fatalf("%s field %d = %#v, want %#v", n.Name, i, n.Fields[i], want[i])
		}
	}
}

func assertTables(t *testing.T, n *Node, want []TableInfo) {
	t.Helper()
	if len(n.Tables) != len(want) {
		t.Fatalf("%s tables len = %d, want %d", n.Name, len(n.Tables), len(want))
	}
	for i := range want {
		if n.Tables[i] != want[i] {
			t.Fatalf("%s table %d = %#v, want %#v", n.Name, i, n.Tables[i], want[i])
		}
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
