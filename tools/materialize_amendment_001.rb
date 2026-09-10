#!/usr/bin/env ruby
# Independently parse, resolve, and materialize Kinbase amendment 001.

require "base64"
require "digest"
require "fileutils"
require "json"
require "optparse"
require "pathname"
require "set"

TARGET = /^In `(spec\/[^`]+)`.*\b(replace|insert)\b.*:$/
SECTION_ROW = /^\| (O-\d{2}) \| (spec\/[^ |]+) \| ([#]{1,6} .+) \|$/
SUPPLEMENT_ROW = /^\| (spec\/[^ |]+\.md) \| `([0-9a-f]{64})` \|$/
BUNDLE_ROW = /^\| (spec\/[^ |]+) \| .+ \|$/
MARKDOWN_LINK = /\]\(([^)#]+\.md)(?:#[^)]+)?\)/
REFERENCE_LINK = /^[ ]{0,3}\[[^\]\r\n]+\]:[ \t]*<?([^ \t>\r\n]+\.md(?:#[^ \t>\r\n]+)?)>?/
AUTOLINK = /<([^<>\s]+\.md(?:#[^<>\s]+)?)>/
SAFE_PATH = %r{\Aspec/[A-Za-z0-9._/-]+\z}
SAFE_LOCAL_MD_TARGET = /\A[A-Za-z0-9._\/-]+\.md\z/

def digest(body)
  Digest::SHA256.hexdigest(body)
end

def validate_document_bytes(body, label)
  raise "#{label} must not contain UTF-8 BOM" if body.start_with?("\xEF\xBB\xBF".b)
  raise "#{label} must be LF-only" if body.include?("\r")
  utf8 = body.dup.force_encoding(Encoding::UTF_8)
  raise "#{label} must be UTF-8" unless utf8.valid_encoding?
end

def quoted_block(lines, start)
  index = start
  index += 1 while index < lines.length && !lines[index].start_with?(">")
  raise "missing quoted block after amendment line #{start + 1}" if index == lines.length

  decoded = []
  while index < lines.length && lines[index].start_with?(">")
    line = lines[index]
    raise "trailing whitespace in blockquote at amendment line #{index + 1}" if line.end_with?(" ", "\t")
    if line == ">"
      decoded << ""
    elsif line.start_with?("> ")
      decoded << line.byteslice(2, line.bytesize - 2)
    else
      raise "noncanonical blockquote at amendment line #{index + 1}"
    end
    index += 1
  end
  [(decoded.join("\n") + "\n").b, index]
end

def parse_operations(amendment)
  validate_document_bytes(amendment, "amendment")
  text = amendment.dup.force_encoding(Encoding::UTF_8)
  raise "invalid amendment UTF-8" unless text.valid_encoding?
  lines = text.split("\n", -1)

  sections = {}
  lines.each do |line|
    match = SECTION_ROW.match(line)
    next unless match
    operation_id, path, heading = match.captures
    raise "duplicate section declaration for #{operation_id}" if sections.key?(operation_id)
    sections[operation_id] = [path, heading]
  end

  operations = []
  lines.each_with_index do |line, index|
    match = TARGET.match(line)
    next unless match
    path, verb = match.captures
    mode = verb == "replace" ? "replace" : "insert"
    source, next_index = quoted_block(lines, index + 1)
    marker_prefix = mode == "replace" ? "with this exact new" : "this new"
    marker_index = next_index
    while marker_index < lines.length && !lines[marker_index].start_with?(marker_prefix)
      raise "missing new-block marker after amendment line #{index + 1}" if TARGET.match?(lines[marker_index])
      marker_index += 1
    end
    raise "missing new-block marker after amendment line #{index + 1}" if marker_index == lines.length
    replacement, = quoted_block(lines, marker_index + 1)

    ordinal = operations.length + 1
    operation_id = format("O-%02d", ordinal)
    declared = sections.fetch(operation_id) { raise "missing section declaration for #{operation_id}" }
    raise "section path mismatch for #{operation_id}" unless declared[0] == path
    operations << {
      "id" => operation_id,
      "ordinal" => ordinal,
      "mode" => mode,
      "path" => path,
      "containing_heading" => declared[1],
      "source" => source,
      "new_body" => replacement
    }
  end

  raise "no overlay operations found" if operations.empty?
  expected_ids = operations.map { |operation| operation.fetch("id") }.sort
  raise "section declaration census does not match operation census" unless sections.keys.sort == expected_ids

  operations.each do |operation|
    operations.each do |other|
      next if operation.fetch("id") == other.fetch("id")
      if operation.fetch("new_body").include?(other.fetch("source"))
        raise "#{operation.fetch('id')}: new bytes contain #{other.fetch('id')} source"
      end
    end
  end
  operations
end

def parse_supplements(amendment)
  text = amendment.dup.force_encoding(Encoding::UTF_8)
  supplements = {}
  text.split("\n", -1).each do |line|
    match = SUPPLEMENT_ROW.match(line)
    next unless match
    path, expected_digest = match.captures
    raise "duplicate supplemental path #{path}" if supplements.key?(path)
    supplements[path] = expected_digest
  end
  raise "expected 2 supplemental artifacts, got #{supplements.length}" unless supplements.length == 2
  supplements
end

def parse_bundle_members(amendment)
  text = amendment.dup.force_encoding(Encoding::UTF_8)
  lines = text.split("\n", -1)
  intro = lines.index { |line| line.start_with?("The bundle members are the rows of this table;") }
  raise "missing bundle-member table" unless intro
  index = intro + 1
  index += 1 while index < lines.length && lines[index] != "| Bundle member | Derivation |"
  raise "missing bundle-member table header" if index == lines.length
  index += 2
  members = []
  while index < lines.length && lines[index].start_with?("|")
    match = BUNDLE_ROW.match(lines[index])
    raise "malformed bundle-member row at line #{index + 1}" unless match
    path = match[1]
    raise "duplicate bundle member #{path}" if members.include?(path)
    members << path
    index += 1
  end
  raise "empty bundle-member table" if members.empty?
  members
end

def validate_authority_path(path)
  raise "unsafe authority path #{path.inspect}" unless SAFE_PATH.match?(path)
  raise "authority path exceeds 255 bytes: #{path.inspect}" if path.b.bytesize > 255
  parts = path.split("/", -1)
  raise "unsafe authority path segment #{path.inspect}" if parts.any? { |part| ["", ".", ".."].include?(part) }
end

def resolve_local_authority_link(source_path, target)
  return nil if target.include?("://")
  target_path = target.split("#", 2).first
  unless !target_path.start_with?("/") &&
      !target_path.include?("%") &&
      !target_path.include?("\\") &&
      SAFE_LOCAL_MD_TARGET.match?(target_path)
    raise "noncanonical local Markdown target #{target.inspect}"
  end
  parts = target_path.split("/", -1)
  if parts.any? { |part| ["", ".", ".."].include?(part) }
    raise "unsafe local Markdown target segment #{target.inspect}"
  end
  resolved = File.join(File.dirname(source_path), target_path)
  validate_authority_path(resolved)
  resolved
end

def reject_noncanonical_local_links(source_path, source_text)
  [REFERENCE_LINK, AUTOLINK].each do |pattern|
    source_text.scan(pattern) do |capture|
      target = capture.is_a?(Array) ? capture.first : capture
      unless target.include?("://")
        raise "noncanonical local Markdown link in #{source_path}: #{target.inspect}"
      end
    end
  end
end

def validate_operation_layout(rows)
  ordered = rows.sort_by { |row| [row.fetch("start"), row.fetch("ordinal")] }
  ordered.group_by { |row| row.fetch("start") }.each do |offset, same_offset|
    if same_offset.length > 1 && same_offset.any? { |row| row.fetch("end") != offset }
      raise "mixed insertion/replacement at same offset"
    end
  end
  cursor = 0
  ordered.map do |row|
    start = row.fetch("start")
    raise "overlapping operation" if start < cursor
    cursor = row.fetch("end")
    row.fetch("id")
  end.join(",")
end

def unique_offset(body, needle, operation_id, path)
  matches = []
  cursor = 0
  while (offset = body.index(needle, cursor))
    matches << offset
    cursor = offset + 1
  end
  raise "#{operation_id}: source occurs #{matches.length} times in #{path}" unless matches.length == 1
  matches.first
end

def occurrence_count(body, needle)
  count = 0
  cursor = 0
  while (offset = body.index(needle, cursor))
    count += 1
    cursor = offset + 1
  end
  count
end

def containing_heading(body, source_start)
  prefix = body.byteslice(0, source_start)
  cursor = 0
  found = nil
  prefix.each_line do |line|
    heading = line.end_with?("\n") ? line.byteslice(0, line.bytesize - 1) : line
    if /\A[#]{1,6} /.match?(heading)
      utf8 = heading.dup.force_encoding(Encoding::UTF_8)
      raise "invalid heading UTF-8" unless utf8.valid_encoding?
      found = [utf8, cursor, heading]
    end
    cursor += line.bytesize
  end
  raise "no containing heading before byte #{source_start}" unless found
  found
end

def section_extent(body, heading_start, heading_bytes)
  heading_level = heading_bytes[/\A#+/].bytesize
  line_end = body.index("\n", heading_start)
  section_start = line_end ? line_end + 1 : body.bytesize
  cursor = section_start
  section_end = body.bytesize
  body.byteslice(section_start, body.bytesize - section_start).each_line do |line|
    candidate = line.end_with?("\n") ? line.byteslice(0, line.bytesize - 1) : line
    match = /\A([#]{1,6}) .+/.match(candidate)
    if match && match[1].bytesize <= heading_level
      section_end = cursor
      break
    end
    cursor += line.bytesize
  end
  [section_start, section_end]
end

def exercise_section_case(test_case)
  body = test_case.fetch("body").encode(Encoding::UTF_8).b
  source = test_case.fetch("source").encode(Encoding::UTF_8).b
  expected_heading = test_case.fetch("heading")
  occurrences = occurrence_count(body, source)
  raise "source occurs #{occurrences} times" unless occurrences == 1
  source_start = body.index(source)
  source_end = source_start + source.bytesize
  heading, heading_start, heading_bytes = containing_heading(body, source_start)
  raise "heading #{heading.inspect} != #{expected_heading.inspect}" unless heading == expected_heading
  heading_occurrences = body.each_line.count do |line|
    candidate = line.end_with?("\n") ? line.byteslice(0, line.bytesize - 1) : line
    candidate == heading_bytes
  end
  raise "heading occurs #{heading_occurrences} times" unless heading_occurrences == 1
  source_has_heading = source.each_line.any? do |line|
    candidate = line.end_with?("\n") ? line.byteslice(0, line.bytesize - 1) : line
    /\A[#]{1,6} .+/.match?(candidate)
  end
  raise "source contains an ATX heading" if source_has_heading
  section_start, section_end = section_extent(body, heading_start, heading_bytes)
  unless source_start >= section_start && source_end <= section_end
    raise "source crosses section extent"
  end
  "contained"
end

def run_self_test_corpus(path)
  corpus_bytes = File.binread(path)
  corpus = JSON.parse(corpus_bytes)
  unless corpus.fetch("schema") == "kinbase-materializer-adversarial-corpus/1"
    raise "wrong self-test corpus schema"
  end
  results = corpus.fetch("cases").map do |test_case|
    case_id = test_case.fetch("id")
    begin
      value = case test_case.fetch("kind")
              when "quoted"
                quoted_block(test_case.fetch("lines"), 0).first.unpack1("H*")
              when "document"
                validate_document_bytes([test_case.fetch("hex")].pack("H*"), "document")
                "ok"
              when "path"
                validate_authority_path(test_case.fetch("path"))
                "ok"
              when "path-repeat"
                candidate = test_case.fetch("prefix") +
                  (test_case.fetch("character") * test_case.fetch("count")) +
                  test_case.fetch("suffix")
                validate_authority_path(candidate)
                "ok"
              when "section"
                exercise_section_case(test_case)
              when "same-offset"
                rows = test_case.fetch("rows")
                if rows.length > 1 && rows.any? { |row| row.fetch("end") != row.fetch("start") }
                  raise "mixed insertion/replacement at same offset"
                end
                "ok"
              when "operation-layout"
                validate_operation_layout(test_case.fetch("rows"))
              when "seam-recount"
                body = (test_case.fetch("left") + test_case.fetch("new") + test_case.fetch("right")).b
                occurrence_count(body, test_case.fetch("needle").b).to_s
              when "link-target"
                resolve_local_authority_link(
                  test_case.fetch("source"), test_case.fetch("target")
                ) || "external"
              when "link-document"
                reject_noncanonical_local_links(
                  test_case.fetch("source"), test_case.fetch("document")
                )
                "ok"
              when "insertion"
                anchor = test_case.fetch("anchor").b
                raise "insertion anchor must end LF" unless anchor.end_with?("\n")
                (anchor + test_case.fetch("new").b).unpack1("H*")
              else
                raise "unknown self-test kind #{test_case.fetch('kind')}"
              end
      status = "ok"
      error = ""
    rescue KeyError, TypeError, RuntimeError => e
      status = "error"
      value = ""
      error = e.message
    end
    unless status == test_case.fetch("expected_status")
      raise "#{case_id}: status #{status} != #{test_case.fetch('expected_status')}"
    end
    if test_case.key?("expected_value") && value != test_case.fetch("expected_value")
      raise "#{case_id}: value #{value.inspect} != #{test_case.fetch('expected_value').inspect}"
    end
    if test_case.key?("expected_error_contains") && !error.include?(test_case.fetch("expected_error_contains"))
      raise "#{case_id}: missing expected error fragment in #{error.inspect}"
    end
    { "id" => case_id, "status" => status }
  end
  {
    "schema" => "kinbase-materializer-adversarial-result/1",
    "corpus_sha256" => digest(corpus_bytes),
    "case_count" => results.length,
    "cases" => results
  }
end

options = {
  root: File.expand_path("..", __dir__),
  amendment: "spec/amendment-001-rust-vast.md",
  manifest: "spec/ratification-manifest.json"
}
OptionParser.new do |parser|
  parser.on("--root PATH") { |value| options[:root] = File.expand_path(value) }
  parser.on("--amendment PATH") { |value| options[:amendment] = value }
  parser.on("--manifest PATH") { |value| options[:manifest] = value }
  parser.on("--plan PATH") { |value| options[:plan] = File.expand_path(value) }
  parser.on("--out PATH") { |value| options[:out] = File.expand_path(value) }
  parser.on("--receipt PATH") { |value| options[:receipt] = File.expand_path(value) }
  parser.on("--self-test-corpus PATH") { |value| options[:self_test_corpus] = File.expand_path(value) }
end.parse!

if options[:self_test_corpus]
  puts JSON.generate(run_self_test_corpus(options.fetch(:self_test_corpus)))
  exit 0
end

%i[plan out receipt].each { |key| raise "--#{key} required" unless options[key] }

root = options.fetch(:root)
amendment_path = File.join(root, options.fetch(:amendment))
manifest_path = File.join(root, options.fetch(:manifest))
amendment = File.binread(amendment_path)
manifest_bytes = File.binread(manifest_path)
plan_bytes = File.binread(options.fetch(:plan))
plan = JSON.parse(plan_bytes)
raise "wrong plan schema" unless plan.fetch("schema") == "kinbase-amendment-overlay/1"

manifest = JSON.parse(manifest_bytes)
expected = manifest.fetch("artifacts").to_h { |row| [row.fetch("path"), row.fetch("sha256")] }
base = {}
expected.each do |path, expected_digest|
  validate_authority_path(path)
  body = File.binread(File.join(root, path))
  validate_document_bytes(body, "base #{path}")
  raise "base mismatch #{path}" unless digest(body) == expected_digest
  base[path] = body
end

operations = parse_operations(amendment)
supplements = parse_supplements(amendment)
bundle_members = parse_bundle_members(amendment)
supplemental_bodies = {}
supplements.each do |path, expected_digest|
  validate_authority_path(path)
  raise "supplement duplicates base path #{path}" if base.key?(path)
  body = File.binread(File.join(root, path))
  validate_document_bytes(body, "supplement #{path}")
  raise "supplement digest mismatch for #{path}" unless digest(body) == expected_digest
  supplemental_bodies[path] = body
end
resolved = []
by_path = Hash.new { |hash, key| hash[key] = [] }
operations.each do |operation|
  operation_id = operation.fetch("id")
  path = operation.fetch("path")
  body = base.fetch(path) { raise "#{operation_id}: target not in base manifest" }
  source = operation.fetch("source")
  replacement = operation.fetch("new_body")
  source_start = unique_offset(body, source, operation_id, path)
  source_end = source_start + source.bytesize
  heading, heading_start, heading_bytes = containing_heading(body, source_start)
  unless heading == operation.fetch("containing_heading")
    raise "#{operation_id}: heading #{heading.inspect} != #{operation.fetch('containing_heading').inspect}"
  end
  heading_occurrences = body.each_line.count do |line|
    candidate = line.end_with?("\n") ? line.byteslice(0, line.bytesize - 1) : line
    candidate == heading_bytes
  end
  raise "#{operation_id}: heading occurs #{heading_occurrences} times" unless heading_occurrences == 1
  source_has_heading = source.each_line.any? do |line|
    candidate = line.end_with?("\n") ? line.byteslice(0, line.bytesize - 1) : line
    /\A[#]{1,6} .+/.match?(candidate)
  end
  if source_has_heading
    raise "#{operation_id}: source contains an ATX heading"
  end
  section_start, section_end = section_extent(body, heading_start, heading_bytes)
  unless source_start >= section_start && source_end <= section_end
    raise "#{operation_id}: source range crosses declared section extent"
  end
  write_start = operation.fetch("mode") == "replace" ? source_start : source_end
  write_end = source_end
  context_start = [0, source_start - 200].max
  context_end = [body.bytesize, source_end + 200].min
  context = body.byteslice(context_start, context_end - context_start)

  receipt_row = {
    "id" => operation_id,
    "ordinal" => operation.fetch("ordinal"),
    "mode" => operation.fetch("mode"),
    "path" => path,
    "containing_heading" => heading,
    "heading_start" => heading_start,
    "heading_sha256" => digest(heading_bytes),
    "heading_occurrences_in_raw_base" => heading_occurrences,
    "section_start" => section_start,
    "section_end" => section_end,
    "context_start" => context_start,
    "context_end" => context_end,
    "context_sha256" => digest(context),
    "context_base64" => Base64.strict_encode64(context),
    "base_sha256" => digest(body),
    "source_start" => source_start,
    "source_end" => source_end,
    "write_start" => write_start,
    "write_end" => write_end,
    "base_byte_before_write_hex" => (write_start.zero? ? nil : body.byteslice(write_start - 1, 1).unpack1("H*")),
    "base_byte_after_write_hex" => (write_end < body.bytesize ? body.byteslice(write_end, 1).unpack1("H*") : nil),
    "new_first_byte_hex" => (replacement.empty? ? nil : replacement.byteslice(0, 1).unpack1("H*")),
    "new_last_byte_hex" => (replacement.empty? ? nil : replacement.byteslice(-1, 1).unpack1("H*")),
    "source_sha256" => digest(source),
    "source_bytes" => source.bytesize,
    "source_base64" => Base64.strict_encode64(source),
    "new_sha256" => digest(replacement),
    "new_bytes" => replacement.bytesize,
    "new_base64" => Base64.strict_encode64(replacement),
    "occurrences_in_raw_base" => 1
  }
  resolved << receipt_row
  by_path[path] << receipt_row.merge("new_body" => replacement)
end

effective = base.dup
by_path.each do |path, rows|
  rows.sort_by! { |row| [row.fetch("write_start"), row.fetch("ordinal")] }
  rows.group_by { |row| row.fetch("write_start") }.each do |offset, same_offset|
    if same_offset.length > 1 && same_offset.any? { |row| row.fetch("write_end") != offset }
      raise "mixed insertion/replacement at #{path}:#{offset}"
    end
  end
  cursor = 0
  chunks = []
  rows.each do |row|
    start = row.fetch("write_start")
    finish = row.fetch("write_end")
    raise "overlap #{row.fetch('id')}" if start < cursor
    chunks << base.fetch(path).byteslice(cursor, start - cursor)
    chunks << row.fetch("new_body")
    cursor = finish
  end
  chunks << base.fetch(path).byteslice(cursor, base.fetch(path).bytesize - cursor)
  effective[path] = chunks.join
end

operations.each_with_index do |operation, index|
  row = resolved.fetch(index)
  body = effective.fetch(operation.fetch("path"))
  source_occurrences = occurrence_count(body, operation.fetch("source"))
  expected_source_occurrences = operation.fetch("mode") == "replace" ? 0 : 1
  unless source_occurrences == expected_source_occurrences
    raise "#{operation.fetch('id')}: source occurs #{source_occurrences} times after materialization; expected #{expected_source_occurrences}"
  end
  heading_bytes = operation.fetch("containing_heading").b
  heading_occurrences = body.each_line.count do |line|
    candidate = line.end_with?("\n") ? line.byteslice(0, line.bytesize - 1) : line
    candidate == heading_bytes
  end
  unless heading_occurrences == 1
    raise "#{operation.fetch('id')}: heading occurs #{heading_occurrences} times after materialization"
  end
  row["source_occurrences_in_effective"] = source_occurrences
  row["heading_occurrences_in_effective"] = heading_occurrences
end

raise "independently derived operation plan disagrees" unless resolved == plan.fetch("operations")
raise "amendment path disagrees" unless plan.fetch("amendment_path") == options.fetch(:amendment)
raise "amendment digest mismatch" unless digest(amendment) == plan.fetch("amendment_sha256")
raise "manifest path disagrees" unless plan.fetch("base_manifest_path") == options.fetch(:manifest)
raise "manifest digest mismatch" unless digest(manifest_bytes) == plan.fetch("base_manifest_sha256")

effective.merge!(supplemental_bodies)
effective[options.fetch(:amendment)] = amendment
unless bundle_members.length == effective.length && bundle_members.to_set == effective.keys.to_set
  raise "bundle-member table disagrees with materialized artifact census"
end

markdown_links = []
effective.keys.sort_by(&:b).each do |source_path|
  source_text = effective.fetch(source_path).dup.force_encoding(Encoding::UTF_8)
  raise "invalid UTF-8 in #{source_path}" unless source_text.valid_encoding?
  reject_noncanonical_local_links(source_path, source_text)
  source_text.scan(MARKDOWN_LINK) do |capture|
    target = capture.first
    resolved_target = resolve_local_authority_link(source_path, target)
    next unless resolved_target
    raise "unbound Markdown authority link #{source_path} -> #{resolved_target}" unless effective.key?(resolved_target)
    markdown_links << { "source" => source_path, "target" => resolved_target }
  end
end

effective.each_key { |path| validate_authority_path(path) }
artifacts = effective.keys.sort_by(&:b).map do |path|
  { "path" => path, "sha256" => digest(effective.fetch(path)), "bytes" => effective.fetch(path).bytesize }
end
unless artifacts.length == bundle_members.length
  raise "authority bundle count #{artifacts.length} != table count #{bundle_members.length}"
end
root_bytes = "kinbase-authority-bundle-v1\nartifact-count\t#{artifacts.length}\n" +
  artifacts.map { |row| "#{row.fetch('path')}\t#{row.fetch('sha256')}\n" }.join
bundle_root = digest(root_bytes)
raise "artifact census disagrees with parsed plan" unless artifacts == plan.fetch("artifacts")
expected_supplements = supplements.keys.sort_by(&:b).map do |path|
  { "path" => path, "sha256" => supplements.fetch(path) }
end
raise "supplement census disagrees with parsed plan" unless expected_supplements == plan.fetch("supplements")
raise "bundle-member table disagrees with parsed plan" unless bundle_members == plan.fetch("bundle_members")
raise "Markdown link census disagrees with parsed plan" unless markdown_links == plan.fetch("markdown_authority_links")
raise "bundle root disagrees with parsed plan" unless bundle_root == plan.fetch("bundle_root_sha256")

receipt = {
  schema: "kinbase-amendment-independent-crosscheck/1",
  algorithm: "independent amendment/table parse, unique raw-base search, heading check, and ascending-offset splice",
  compared_plan_sha256: digest(plan_bytes),
  amendment_sha256: digest(amendment),
  operation_count: resolved.length,
  operations: resolved,
  independently_derived_operations_sha256: digest(JSON.generate(resolved)),
  supplements: expected_supplements,
  bundle_members: bundle_members,
  markdown_authority_links: markdown_links,
  artifacts: artifacts,
  bundle_root_method: "sha256(kinbase-authority-bundle-v1 LF, artifact-count TAB N LF, then path TAB artifact_sha256 LF; NFC-safe paths sorted by raw UTF-8 bytes)",
  bundle_root_sha256: bundle_root
}

FileUtils.mkdir_p(options.fetch(:out))
effective.each { |path, body| File.binwrite(File.join(options.fetch(:out), File.basename(path)), body) }
FileUtils.mkdir_p(File.dirname(options.fetch(:receipt)))
File.write(options.fetch(:receipt), JSON.pretty_generate(receipt) + "\n")
puts bundle_root
