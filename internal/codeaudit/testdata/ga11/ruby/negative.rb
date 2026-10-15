# Negative control for the Ruby TAA rule pack: benign code that must not
# produce a single finding from any of the thirteen families. Every construct
# here is the near miss for one of them - an environment read, a file read, a
# copy, a log line, a safe deserializer - so that a rule whose name predicate
# has been lost shows up as a hit on this file rather than as silence.
require "csv"
require "fileutils"
require "yaml"

module Reporting
  # Aggregates a result table and renders a one-line description of it.
  class Summary
    attr_reader :rows

    def initialize(rows)
      @rows = rows
    end

    def mean(values)
      return 0 if values.empty?

      values.sum / values.length
    end

    def column(name)
      @rows.map { |row| row.fetch(name) }
    end

    def describe
      heights = column("height")
      "rows=#{@rows.length} mean_height=#{format('%.2f', mean(heights))}"
    end
  end
end

def main
  base = ENV.fetch("HOME", "/tmp")
  config = YAML.safe_load(File.read("config/app.yml"))
  rows = CSV.read(File.join("data", "input.csv"), headers: true)
  summary = Reporting::Summary.new(rows)
  target = File.join(base, "reports", "summary.csv")

  FileUtils.mkdir_p(File.dirname(target))
  FileUtils.cp("templates/report.pdf", File.join("reports", "report.pdf"))
  File.write(target, summary.describe)
  logger.info(summary.describe)
  logger.debug("config sections: #{config.keys.length}")
  puts "done"
end

main
