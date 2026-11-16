package mock

import (
	"archive/zip"
	"bytes"
	"fmt"
	"log"
	"sort"
)

// Audit samples are a built-in corpus: one archive per static rule, each built
// so it fires exactly the rule it is named for and nothing else. They exist
// because the workbench is a test tool — an operator needs a way to see a rule
// actually fire without hand-writing a package that dodges every earlier rule.
//
// The corpus mirrors the engine's matching order rather than a hand-picked
// subset of "interesting" cases. Tier 1 scans a line at a time and stops at the
// first match, so a sample that fires two rules is a bug in the sample, not a
// feature: it would make the rule it names look correct while never testing it.
// Every snippet below therefore avoids the vocabulary of the rules ahead of it,
// and the samples that must dodge a whole family say so in place.
type auditSample struct {
	// RuleID is the rule the archive is expected to trigger, and the key used to
	// decide whether the sample is already seeded.
	RuleID string
	// Title and Note are shown in the console so a sample explains itself.
	Title string
	Note  string
	// Files is the archive's contents by path.
	Files map[string][]byte
}

// samplePickleProtocol4 is a real pickle stream naming posix.system. The
// binary channel parses the interpreter records, so the payload never has to be
// executed for PKL_001 to fire; a real `.pkl` looks exactly like this.
var samplePickleProtocol4 = []byte("\x80\x04cposix\nsystem\n.")

func auditSamples() []auditSample {
	return []auditSample{
		{
			RuleID: "NET_001",
			Title:  "HTTP 出站请求",
			Note:   "requests.get 直接外联，命中网络请求规则。",
			Files: map[string][]byte{
				"net_http.py": []byte("import requests\n\n\ndef fetch(addr):\n    return requests.get(addr)\n"),
			},
		},
		{
			RuleID: "NET_002",
			Title:  "原始 Socket",
			Note:   "绕过 HTTP 客户端直接建 socket，命中底层网络规则。",
			Files: map[string][]byte{
				"net_socket.py": []byte("import socket\n\n\ndef open_channel():\n    return socket.socket()\n"),
			},
		},
		{
			RuleID: "CMD_001",
			Title:  "命令执行",
			Note:   "os.system 调用 shell，命中命令执行规则。",
			Files: map[string][]byte{
				"cmd_exec.py": []byte("import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"),
			},
		},
		{
			RuleID: "OBF_001",
			Title:  "编码与反序列化",
			Note:   "base64 解码，命中代码混淆规则。",
			Files: map[string][]byte{
				"obf_base64.py": []byte("import base64\n\n\ndef unpack(blob):\n    return base64.b64decode(blob)\n"),
			},
		},
		{
			RuleID: "DYN_001",
			Title:  "动态执行",
			Note:   "eval 在运行时求值，命中动态执行规则。",
			Files: map[string][]byte{
				"dyn_eval.py": []byte("def calculate(expr):\n    return eval(expr)\n"),
			},
		},
		{
			RuleID: "FIL_001",
			Title:  "敏感文件读取",
			Note:   "读取 .env，命中敏感文件读取规则。",
			Files: map[string][]byte{
				"fil_env.py": []byte("def load_settings():\n    return open(\".env\").read()\n"),
			},
		},
		{
			RuleID: "ENV_001",
			Title:  "敏感环境变量",
			Note:   "读取 API_KEY，命中环境变量规则；不写 open(...) 以免先命中 FIL_001。",
			Files: map[string][]byte{
				"env_key.py": []byte("import os\n\n\ndef api_token():\n    return os.getenv(\"API_KEY\")\n"),
			},
		},
		{
			RuleID: "PER_001",
			Title:  "持久化后门",
			Note:   "crontab 字面量命中持久化规则；刻意不写 os.system，否则先命中 CMD_001。",
			Files: map[string][]byte{
				"per_cron.py": []byte("SCHEDULE = \"crontab -l\"\n\n\ndef show():\n    return SCHEDULE\n"),
			},
		},
		{
			RuleID: "EXF_001",
			Title:  "编码后外传",
			Note:   "序列化后直接 POST；不用 base64，否则先命中 OBF_001。",
			Files: map[string][]byte{
				"exf_send.py": []byte("import json\n\n\ndef report(client, payload):\n    client.post(json.dumps(payload))\n"),
			},
		},
		{
			RuleID: "EMB_001",
			Title:  "原始数据写入输出",
			Note:   "把训练数据整体 torch.save，命中结果嵌入数据规则。",
			Files: map[string][]byte{
				"emb_save.py": []byte("import torch\n\n\ndef dump(train_data):\n    torch.save(train_data, \"model.pt\")\n"),
			},
		},
		{
			RuleID: "EMB_002",
			Title:  "原始数据复制到导出目录",
			Note:   "复制到 output 目录；路径里不写 data，否则先命中 EMB_001。",
			Files: map[string][]byte{
				"emb_export.py": []byte("import shutil\n\n\ndef export(src):\n    shutil.copy(src, \"output/payload.txt\")\n"),
			},
		},
		{
			RuleID: "EMB_003",
			Title:  "数据打印到日志",
			Note:   "直接 print 数据集，命中日志泄露规则。",
			Files: map[string][]byte{
				"emb_print.py": []byte("def debug(train_dataset):\n    print(train_dataset)\n"),
			},
		},
		{
			RuleID: "EMB_004",
			Title:  "编码进权重",
			Note:   "把 state_dict 编码后写出，命中隐写泄露规则。",
			Files: map[string][]byte{
				"emb_stego.py": []byte("def stash(state_dict, encode):\n    encoded = encode(state_dict)\n    return encoded\n"),
			},
		},

		// ── Binary channel: constructed bytes, not source ──
		{
			RuleID: "PKL_001",
			Title:  "恶意 pickle 目标",
			Note:   "协议 4 的 pickle 直接调用 posix.system，命中 pickle 反序列化规则。",
			Files: map[string][]byte{
				"checkpoint/data.pkl": samplePickleProtocol4,
			},
		},
		{
			RuleID: "CMD_002",
			Title:  "二进制中的 shell 路径",
			Note:   "含 NUL 的字节串被判为 raw，字符串证据里出现 /bin/bash。",
			Files: map[string][]byte{
				"blobs/payload.bin": []byte("\x00/bin/bash\x00"),
			},
		},
		{
			RuleID: "PER_002",
			Title:  "二进制中的 cron 路径",
			Note:   "字符串证据里出现 /etc/cron.d，命中持久化（二进制）规则。",
			Files: map[string][]byte{
				"blobs/persist.bin": []byte("\x00/etc/cron.d/backdoor\x00"),
			},
		},
		{
			RuleID: "FIL_002",
			Title:  "二进制中的敏感文件路径",
			Note:   "字符串证据里出现 /etc/shadow。",
			Files: map[string][]byte{
				"blobs/creds.bin": []byte("\x00/etc/shadow\x00"),
			},
		},
		{
			RuleID: "ENV_002",
			Title:  "二进制中的密钥变量名",
			Note:   "字符串证据里出现 AWS_SECRET_ACCESS_KEY；该规则区分大小写。",
			Files: map[string][]byte{
				"blobs/env.bin": []byte("\x00AWS_SECRET_ACCESS_KEY\x00"),
			},
		},
		{
			RuleID: "clean",
			Title:  "正常训练脚本（对照）",
			Note:   "不含任何触发表述的常规训练循环，用来验证「通过」结论。",
			Files: map[string][]byte{
				"train.py": []byte(
					"import torch\n\n\n" +
						"def train(model, loader, optimizer, epochs=3):\n" +
						"    for epoch in range(epochs):\n" +
						"        for batch in loader:\n" +
						"            loss = model(batch)\n" +
						"            optimizer.zero_grad()\n" +
						"            loss.backward()\n" +
						"            optimizer.step()\n" +
						"        print(f\"epoch {epoch + 1} loss {loss.item():.4f}\")\n" +
						"    return model\n"),
			},
		},
	}
}

// sampleArchiveName is the name the sample appears under in the file area. The
// rule id is part of it so the entry is identifiable without opening it.
func sampleArchiveName(s auditSample) string {
	return "样例-" + s.RuleID + ".zip"
}

// buildSampleArchive packs one sample as a zip in memory. Stored (uncompressed)
// entries keep the bytes readable for anyone inspecting the corpus, and the size
// is negligible.
func buildSampleArchive(s auditSample) ([]byte, error) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	// Sorted paths keep the archive byte-identical across runs, which makes a
	// seeded sample comparable between deployments.
	for _, name := range sortedKeys(s.Files) {
		entry, err := writer.Create(name)
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", name, err)
		}
		if _, err := entry.Write(s.Files[name]); err != nil {
			return nil, fmt.Errorf("write %s: %w", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sortedKeys(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// seedAuditSamples makes sure every built-in sample is present in the file area,
// encrypting and storing the ones that are not. It runs once at startup and is
// idempotent: an entry whose Sample field names the rule is left untouched, so
// a restart does not grow the list and an operator's delete is undone only on
// the next restart (which is what makes the corpus a fixture rather than state).
func seedAuditSamples(store *auditFileStore, keys *workbenchKeys) {
	if store == nil || !keys.ready() {
		return
	}
	present := make(map[string]bool)
	for _, entry := range store.list() {
		if entry.Sample != "" {
			present[entry.Sample] = true
		}
	}
	seeded := 0
	for _, sample := range auditSamples() {
		if present[sample.RuleID] {
			continue
		}
		archive, err := buildSampleArchive(sample)
		if err != nil {
			log.Printf("audit sample %s: build failed: %v", sample.RuleID, err)
			continue
		}
		if _, err := store.saveSample(archive, sampleArchiveName(sample), sample.RuleID, sample.Title, sample.Note, keys); err != nil {
			log.Printf("audit sample %s: store failed: %v", sample.RuleID, err)
			continue
		}
		seeded++
	}
	if seeded > 0 {
		log.Printf("audit samples: seeded %d built-in rule samples into the file area", seeded)
	}
}

// seedSamples puts the built-in corpus in the file area so each static rule can
// be triggered from the console. The server calls it once after construction,
// rather than the constructor calling it, so a test that builds a runner gets
// only the entries it creates.
func (r *localAuditRunner) seedSamples() {
	seedAuditSamples(r.files, r.keys)
}
