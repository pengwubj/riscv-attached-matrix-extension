#!/usr/bin/env ruby
# frozen_string_literal: true

# Check every instruction encoding for malformed fields, diagram/decode
# mismatches, exact duplicates, and partial decode-space overlaps.

attributes_path = File.join(__dir__, "..", "src", "instruction-encoding-allocations.adoc")
instructions_path = File.join(__dir__, "..", "src", "instructions.adoc")
instructions_source = File.read(instructions_path)

attributes = {}
File.foreach(attributes_path) do |line|
  match = line.match(/^:([a-z0-9-]+):\s+(\S+)$/)
  attributes[match[1]] = match[2] if match
end

abort "no managed encoding attributes found" if attributes.empty?

entries = []
instruction = nil
used_attributes = []

opcode_mask = 0x0000007f
dest_mask = 0x00000f80
funct3_mask = 0x00007000
src1_mask = 0x000f8000
src2_mask = 0x01f00000
funct7_mask = 0xfe000000
skeleton_mask = opcode_mask | funct3_mask | funct7_mask

File.foreach(instructions_path) do |line|
  heading = line.match(/^=== `([^`]+)`/)
  instruction = heading[1] if heading
  next unless instruction && line.start_with?("{\"reg\":")

  resolved = line.gsub(/\{([a-z0-9-]+)\}/) do
    name = Regexp.last_match(1)
    abort "unknown encoding attribute {#{name}} in #{instruction}" unless attributes.key?(name)

    used_attributes << name
    attributes[name]
  end

  resolved.scan(/"bits":(\d+),"name":\s*(0x[0-9a-f]+|\d+)/).each do |width_text, value_text|
    width = width_text.to_i
    field_value = value_text.start_with?("0x") ? value_text.to_i(16) : value_text.to_i
    abort "#{instruction} encoding value #{value_text} does not fit in #{width} bits" if field_value >= (1 << width)
  end

  # Build a fixed-bit mask/value pair.  Exact WaveDrom equality is insufficient
  # for detecting overlap between an encoding with a variable operand field and
  # a more-specific encoding that fixes some of those operand bits.
  position = 0
  mask = 0
  value = 0
  resolved.scan(/"bits":(\d+),"name":\s*("[^"]+"|0x[0-9a-f]+|\d+)/) do |width_text, token|
    width = width_text.to_i
    unless token.start_with?('"')
      field_value = token.start_with?("0x") ? token.to_i(16) : token.to_i
      field_mask = ((1 << width) - 1) << position
      mask |= field_mask
      value |= field_value << position
    end
    position += width
  end
  abort "#{instruction} encoding is #{position} bits, expected 32" unless position == 32

  unless (mask & skeleton_mask) == skeleton_mask
    abort "#{instruction} must retain fixed funct7[31:25], funct3[14:12], and opcode[6:0] fields"
  end
  abort "#{instruction} must use CUSTOM-1 opcode 0x2b" unless (value & opcode_mask) == 0x2b
  abort "#{instruction} has no destination operand in bits 11:7; R0 is not defined" unless (mask & dest_mask).zero?

  src1_fixed = (mask & src1_mask) == src1_mask
  src2_fixed = (mask & src2_mask) == src2_mask
  format = if !src2_fixed
             abort "#{instruction} uses src2[24:20] but fixes src1[19:15]" if src1_fixed
             "R3"
           elsif !src1_fixed
             "R2"
           else
             "R1"
           end

  extension = case format
              when "R2" then (value >> 20) & 0x1f
              when "R1" then (value >> 15) & 0x3ff
              end
  entries << { name: instruction, mask: mask, value: value, format: format,
               bank: value & skeleton_mask, funct7: (value >> 25) & 0x7f,
               funct3: (value >> 12) & 0x7, extension: extension }
end

unused = attributes.keys - used_attributes.uniq
abort "unused managed encoding attributes: #{unused.sort.join(', ')}" unless unused.empty?

# Keep the Chapter 2 instruction list authoritative for classification and
# guarantee that every detailed instruction appears in exactly one list.
unallocated_names = []
instructions_source.scan(/^=== `([^`]+)`\n(.*?)(?=^=== `|\z)/m) do |name, section|
  next unless section.include?("This specification does not assign an instruction encoding.")

  abort "#{name} is marked unallocated but has an encoding diagram" if section.include?('{"reg":')
  unallocated_names << name
end

category_by_instruction = {}
current_category = nil
instructions_source.split("\n<<<\n", 2).first.each_line do |line|
  heading = line.match(/^(.+)::$/)
  current_category = heading[1] if heading
  mnemonic = line.match(/^a\| `([^\s`]+)/)
  next unless mnemonic
  abort "#{mnemonic[1]} is listed in multiple instruction categories" if category_by_instruction.key?(mnemonic[1])
  abort "#{mnemonic[1]} has no instruction category" unless current_category

  category_by_instruction[mnemonic[1]] = current_category
end
detailed_names = entries.map { |entry| entry[:name] } + unallocated_names
missing_categories = detailed_names - category_by_instruction.keys
extra_categories = category_by_instruction.keys - detailed_names
abort "instructions missing from Chapter 2 categories: #{missing_categories.join(', ')}" unless missing_categories.empty?
abort "Chapter 2 categories contain unknown instructions: #{extra_categories.join(', ')}" unless extra_categories.empty?

funct3_values = entries.map { |entry| entry[:funct3] }.uniq
abort "AME instructions must all use funct3=0, found #{funct3_values.sort.join(', ')}" unless funct3_values == [0]

reserved_funct7 = {
  "R3" => [0x35],
  "R2" => [],
  "R1" => []
}
expected_funct7 = {
  "R3" => (0x00..0x50).to_a - reserved_funct7.fetch("R3"),
  "R2" => [0x51, 0x52],
  "R1" => [0x53]
}
expected_funct7.each do |format_name, expected|
  actual = entries.select { |entry| entry[:format] == format_name }
                  .map { |entry| entry[:funct7] }.uniq.sort
  abort "#{format_name} funct7 banks #{actual.inspect}, expected #{expected.inspect}" unless actual == expected
end

# Keep every WaveDrom operand field synchronized with the normative
# Decode Variables block.  Collision checking alone cannot detect a diagram
# that assigns an operand to different bits than the pseudocode reads.
field_errors = []
instructions_source.scan(/^=== `([^`]+)`\n(.*?)(?=^=== `|\z)/m) do |name, section|
  diagram = section.lines.find { |line| line.start_with?('{"reg":') }
  next unless diagram

  position = 0
  fields = {}
  diagram.scan(/"bits":(\d+),"name":\s*(\{[^}]+\}|"[^"]+"|0x[0-9a-f]+|\d+)/) do |width_text, token|
    width = width_text.to_i
    fields[token[1...-1]] = [position + width - 1, position] if token.start_with?('"')
    position += width
  end

  decoded = {}
  section.scan(/(?:Bits|UInt|SInt)<\d+>\s+(\w+)\s*=\s*\$encoding\[(\d+)(?::(\d+))?\]/) do |field, hi, lo|
    decoded[field] = [hi.to_i, (lo || hi).to_i]
  end

  fields.each do |field, range|
    if !decoded.key?(field)
      field_errors << "#{name} does not decode operand #{field} from diagram bits #{range.join(':')}"
    elsif decoded[field] != range
      field_errors << "#{name} operand #{field}: diagram #{range.join(':')}, decode #{decoded[field].join(':')}"
    end
  end

  mnemonic_match = section.match(/^`#{Regexp.escape(name)}(?:\s+([^`]+))?`$/)
  if !mnemonic_match
    field_errors << "#{name} has no parseable Mnemonic line"
  else
    mnemonic_operands = mnemonic_match[1].to_s.split(',').map(&:strip).reject(&:empty?)
    diagram_operands = fields.keys
    unless mnemonic_operands == diagram_operands
      field_errors << "#{name} mnemonic operands #{mnemonic_operands.join(', ')} do not match diagram operands #{diagram_operands.join(', ')}"
    end
  end
end
abort "managed encoding/decode mismatch:\n  #{field_errors.join("\n  ")}" unless field_errors.empty?

# The same (funct7, funct3, opcode) bank cannot mix arities.  Otherwise a
# more-specific R1/R2 decode would be a subset of an R2/R3 decode even if the
# currently allocated xfunct values happened not to collide.
mixed_banks = entries.group_by { |entry| entry[:bank] }.map do |bank, members|
  formats = members.map { |entry| entry[:format] }.uniq
  [bank, formats, members] if formats.length > 1
end.compact
unless mixed_banks.empty?
  mixed_banks.each do |bank, formats, members|
    warn format("mixed format bank 0x%08x (%s): %s", bank, formats.join("/"),
                members.map { |entry| entry[:name] }.join(", "))
  end
  exit 1
end

# Within R2/R1, consume the extension field densely before opening another
# funct7 bank.  This turns the space-saving policy into a checked invariant
# rather than a documentation preference.
reserved_extensions = {
  ["R2", 0x51] => [9]
}
[["R2", 32], ["R1", 1024]].each do |format_name, capacity|
  entries.select { |entry| entry[:format] == format_name }
         .group_by { |entry| entry[:funct3] }.each do |funct3, family|
    partial_banks = []
    family.group_by { |entry| entry[:funct7] }.each do |funct7, bank_entries|
      values = bank_entries.map { |entry| entry[:extension] }.sort
      expected = (0...capacity).to_a - reserved_extensions.fetch([format_name, funct7], [])
      expected = expected.take(values.length)
      unless values == expected
        abort format("%s funct3=%d funct7=0x%02x has sparse extension values: %s",
                     format_name, funct3, funct7, values.join(","))
      end
      bank_capacity = capacity - reserved_extensions.fetch([format_name, funct7], []).length
      partial_banks << funct7 if values.length < bank_capacity
    end
    next if partial_banks.length <= 1

    abort format("%s funct3=%d opens multiple partial funct7 banks: %s",
                 format_name, funct3, partial_banks.map { |value| format("0x%02x", value) }.join(", "))
  end
end

collisions = entries.combination(2).select do |left, right|
  common_mask = left[:mask] & right[:mask]
  ((left[:value] ^ right[:value]) & common_mask).zero?
end

unless collisions.empty?
  collisions.each do |left, right|
    kind = left[:mask] == right[:mask] && left[:value] == right[:value] ? "exact duplicate" : "decode overlap"
    warn "instruction encoding #{kind}: #{left[:name]}, #{right[:name]}"
  end
  exit 1
end

format_counts = entries.group_by { |entry| entry[:format] }.transform_values(&:length)
puts "checked #{entries.length} instruction encodings " \
     "(R3=#{format_counts.fetch('R3', 0)}, R2=#{format_counts.fetch('R2', 0)}, " \
     "R1=#{format_counts.fetch('R1', 0)}): single funct3=0, stable selector skeleton, exclusive format banks, " \
     "dense xfunct allocation, unique Chapter 2 classification, " \
     "fields match decode variables, no duplicates or overlaps"
