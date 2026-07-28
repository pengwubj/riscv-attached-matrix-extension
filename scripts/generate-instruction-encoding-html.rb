#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate a standalone, review-oriented HTML catalog of every AME encoding.

require "cgi"

root = File.expand_path("..", __dir__)
allocations_path = File.join(root, "src", "instruction-encoding-allocations.adoc")
instructions_path = File.join(root, "src", "instructions.adoc")
output_path = File.join(root, "INSTRUCTION_ENCODINGS.html")

attributes = {}
File.foreach(allocations_path) do |line|
  match = line.match(/^:([a-z0-9-]+):\s+(\S+)$/)
  attributes[match[1]] = match[2] if match
end

instructions_source = File.read(instructions_path)

# Chapter 2's instruction list is the classification source of truth.  Do not
# infer categories from mnemonic spelling: suffixes describe semantics, not
# document taxonomy.
category_by_instruction = {}
current_category = nil
instructions_source.split("\n<<<\n", 2).first.each_line do |line|
  heading = line.match(/^(.+)::$/)
  current_category = heading[1] if heading
  mnemonic = line.match(/^a\| `([^\s`]+)/)
  next unless mnemonic
  abort "instruction #{mnemonic[1]} appears in multiple Chapter 2 categories" if category_by_instruction.key?(mnemonic[1])
  abort "instruction #{mnemonic[1]} has no Chapter 2 category" unless current_category

  category_by_instruction[mnemonic[1]] = current_category
end

entries = []
unallocated_names = []
instructions_source.scan(/^=== `([^`]+)`\n(.*?)(?=^=== `|\z)/m) do |name, section|
  diagram = section.lines.find { |line| line.start_with?('{"reg":') }
  unless diagram
    if section.include?("This specification does not assign an instruction encoding.")
      unallocated_names << name
      next
    end

    abort "#{name} has no WaveDrom encoding"
  end

  mnemonic = section[/Mnemonic::\n`([^`]+)`/, 1]
  synopsis = section[/Synopsis::\n([^\n]+)/, 1].to_s.strip
  position = 0
  mask = 0
  match_value = 0
  fields = []

  diagram.scan(/"bits":(\d+),"name":\s*(\{[^}]+\}|"[^"]+"|0x[0-9a-f]+|\d+)/) do |width_text, token|
    width = width_text.to_i
    lo = position
    hi = position + width - 1
    if token.start_with?('"')
      fields << { kind: :operand, name: token[1...-1], width: width, hi: hi, lo: lo }
    else
      attribute = token[/\A\{([^}]+)\}\z/, 1]
      value_text = attribute ? attributes.fetch(attribute) : token
      value = value_text.start_with?("0x") ? value_text.to_i(16) : value_text.to_i
      mask |= ((1 << width) - 1) << lo
      match_value |= value << lo
      fields << { kind: :fixed, value: value, width: width, hi: hi, lo: lo }
    end
    position += width
  end
  abort "#{name} encoding is #{position} bits, expected 32" unless position == 32

  by_range = fields.to_h { |field| [[field[:hi], field[:lo]], field] }
  format = if by_range.fetch([24, 20])[:kind] == :operand
             "R3"
           elsif by_range.fetch([19, 15])[:kind] == :operand
             "R2"
           else
             "R1"
           end
  category = category_by_instruction.fetch(name) do
    abort "#{name} is missing from the Chapter 2 instruction classification"
  end
  entries << { name: name, mnemonic: mnemonic, synopsis: synopsis, fields: fields,
               mask: mask, value: match_value, format: format, category: category }
end

extra_classifications = category_by_instruction.keys - entries.map { |entry| entry[:name] } - unallocated_names
abort "Chapter 2 classifies unknown instructions: #{extra_classifications.join(', ')}" unless extra_classifications.empty?

overlaps = entries.combination(2).select do |left, right|
  common_mask = left[:mask] & right[:mask]
  ((left[:value] ^ right[:value]) & common_mask).zero?
end

escape = ->(text) { CGI.escapeHTML(text.to_s) }
role = lambda do |entry, field|
  return field[:name] if field[:kind] == :operand
  case [field[:hi], field[:lo]]
  when [31, 25] then "funct7"
  when [24, 20] then entry[:format] == "R1" ? "xfunct10[9:5]" : "xfunct5"
  when [19, 15] then "xfunct10[4:0]"
  when [14, 12] then "funct3"
  when [6, 0] then "opcode"
  else "fixed"
  end
end

field_html = lambda do |entry|
  entry[:fields].sort_by { |field| -field[:hi] }.map do |field|
    label = role.call(entry, field)
    value = field[:kind] == :fixed ? format("0x%x", field[:value]) : field[:name]
    klass = field[:kind] == :fixed ? "fixed" : "operand"
    title = "bits #{field[:hi]}:#{field[:lo]}"
    %(<span class="bit #{klass} w#{field[:width]}" title="#{title}"><b>#{escape.call(label)}</b><small>#{escape.call(value)}</small></span>)
  end.join
end

format_counts = entries.group_by { |entry| entry[:format] }.transform_values(&:length)
category_counts = entries.group_by { |entry| entry[:category] }.transform_values(&:length)

rows = entries.sort_by { |entry| [entry[:category], entry[:name]] }.map.with_index(1) do |entry, index|
  %(<tr data-format="#{entry[:format]}" data-category="#{escape.call(entry[:category])}">
    <td class="num">#{index}</td>
    <td><span class="tag #{entry[:format].downcase}">#{entry[:format]}</span></td>
    <td><code>#{escape.call(entry[:name])}</code></td>
    <td><code>#{escape.call(entry[:mnemonic])}</code><div class="synopsis">#{escape.call(entry[:synopsis])}</div></td>
    <td><div class="bitbar">#{field_html.call(entry)}</div></td>
    <td><code>0x#{format('%08x', entry[:mask])}</code></td>
    <td><code>0x#{format('%08x', entry[:value])}</code></td>
  </tr>)
end.join("\n")

category_options = category_counts.sort.map do |category, count|
  %(<option value="#{escape.call(category)}">#{escape.call(category)} (#{count})</option>)
end.join

html = <<~HTML
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AME instruction encoding review</title>
    <style>
      :root { --ink:#172033; --muted:#637083; --line:#dbe1ea; --paper:#fff; --bg:#f4f6f9;
        --fixed:#e7efff; --fixed-border:#8ca9e8; --operand:#e8f7ee; --operand-border:#84c79b; }
      * { box-sizing:border-box; } body { margin:0; color:var(--ink); background:var(--bg);
        font:14px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
      main { max-width:1800px; margin:auto; padding:28px; } h1 { margin:0 0 6px; font-size:28px; }
      h2 { margin:30px 0 12px; } p { color:var(--muted); } code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
      .cards { display:grid; grid-template-columns:repeat(5,minmax(130px,1fr)); gap:12px; margin:20px 0; }
      .card { background:var(--paper); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
      .card strong { display:block; font-size:24px; } .card span { color:var(--muted); }
      .formats { display:grid; gap:10px; } .format-row { display:grid; grid-template-columns:54px 1fr; align-items:center;
        background:var(--paper); border:1px solid var(--line); border-radius:9px; padding:10px; }
      .format-row > b { font-size:16px; } .note { border-left:4px solid #5777c8; padding:8px 12px; background:#eef3ff; }
      .toolbar { position:sticky; top:0; z-index:4; display:flex; gap:10px; flex-wrap:wrap; padding:12px;
        margin:20px 0 10px; background:rgba(244,246,249,.94); backdrop-filter:blur(8px); border:1px solid var(--line); border-radius:10px; }
      input,select { border:1px solid #bfc8d6; border-radius:7px; background:white; padding:8px 10px; min-width:180px; }
      input { flex:1; min-width:260px; } .table-wrap { overflow:auto; background:white; border:1px solid var(--line); border-radius:10px; }
      table { border-collapse:collapse; width:100%; min-width:1450px; } th { background:#eef1f6;
        text-align:left; font-size:12px; letter-spacing:.03em; text-transform:uppercase; }
      th,td { border-bottom:1px solid var(--line); padding:9px 10px; vertical-align:middle; } tbody tr:hover { background:#fafcff; }
      .num { color:var(--muted); text-align:right; } .synopsis { color:var(--muted); font-size:12px; margin-top:3px; }
      .tag { display:inline-block; min-width:32px; text-align:center; padding:3px 6px; border-radius:999px; font-weight:700; }
      .tag.r3 { background:#dff4e7; color:#17653a; } .tag.r2 { background:#e5edff; color:#2b4d9d; } .tag.r1 { background:#fae9d2; color:#895315; }
      .bitbar { display:flex; min-width:620px; height:48px; } .bit { display:flex; flex-direction:column; justify-content:center;
        text-align:center; overflow:hidden; border:1px solid; border-right:0; padding:2px 4px; white-space:nowrap; }
      .bit:first-child { border-radius:6px 0 0 6px; } .bit:last-child { border-right:1px solid; border-radius:0 6px 6px 0; }
      .bit.fixed { background:var(--fixed); border-color:var(--fixed-border); } .bit.operand { background:var(--operand); border-color:var(--operand-border); }
      .bit small { display:block; opacity:.72; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
      .w3 { flex:3 } .w5 { flex:5 } .w7 { flex:7 } .hidden { display:none; }
      footer { margin:18px 0; color:var(--muted); }
      @media print { body { background:white; } main { max-width:none; padding:10px; } .toolbar { display:none; }
        .table-wrap { overflow:visible; border:0; } table { min-width:0; font-size:9px; } th { position:static; } .bitbar { min-width:360px; height:34px; }
        .cards { grid-template-columns:repeat(5,1fr); } }
    </style>
  </head>
  <body><main>
    <h1>AME instruction encoding review</h1>
    <p>Standalone review artifact generated from <code>src/instructions.adoc</code>. Decoder rule: <code>(word &amp; mask) == match</code>.</p>
    <div class="cards">
      <div class="card"><strong>#{entries.length}</strong><span>instructions</span></div>
      <div class="card"><strong>#{format_counts.fetch('R3', 0)}</strong><span>R3 encodings</span></div>
      <div class="card"><strong>#{format_counts.fetch('R2', 0)}</strong><span>R2 encodings</span></div>
      <div class="card"><strong>#{format_counts.fetch('R1', 0)}</strong><span>R1 encodings</span></div>
      <div class="card"><strong>#{overlaps.length}</strong><span>decode overlaps</span></div>
    </div>

    <h2>Encoding formats</h2>
    <p class="note"><b>Invariant:</b> <code>funct7[31:25]</code>, <code>funct3[14:12]</code>, and <code>opcode[6:0]</code> remain independent fields. Every instruction uses <code>funct3=000</code>; R0 is not defined.</p>
    <p>R3 occupies <code>funct7=0x00..0x50</code> except reserved value <code>0x35</code>. R2 uses bank <code>0x51</code> with <code>xfunct5=0..31</code> except reserved value <code>0x09</code>, then continues in bank <code>0x52</code>. R1 uses bank <code>0x53</code> with <code>xfunct10=0..1</code>. The 44 <code>funct7</code> values <code>0x54..0x7f</code> remain unallocated.</p>
    <div class="formats">
      <div class="format-row"><b>R3</b><div class="bitbar"><span class="bit fixed w7"><b>funct7</b><small>31:25</small></span><span class="bit operand w5"><b>src2</b><small>24:20</small></span><span class="bit operand w5"><b>src1</b><small>19:15</small></span><span class="bit fixed w3"><b>funct3=0</b><small>14:12</small></span><span class="bit operand w5"><b>dest</b><small>11:7</small></span><span class="bit fixed w7"><b>opcode</b><small>6:0</small></span></div></div>
      <div class="format-row"><b>R2</b><div class="bitbar"><span class="bit fixed w7"><b>funct7</b><small>31:25</small></span><span class="bit fixed w5"><b>xfunct5</b><small>24:20</small></span><span class="bit operand w5"><b>src1</b><small>19:15</small></span><span class="bit fixed w3"><b>funct3=0</b><small>14:12</small></span><span class="bit operand w5"><b>dest</b><small>11:7</small></span><span class="bit fixed w7"><b>opcode</b><small>6:0</small></span></div></div>
      <div class="format-row"><b>R1</b><div class="bitbar"><span class="bit fixed w7"><b>funct7</b><small>31:25</small></span><span class="bit fixed w5"><b>xfunct10[9:5]</b><small>24:20</small></span><span class="bit fixed w5"><b>xfunct10[4:0]</b><small>19:15</small></span><span class="bit fixed w3"><b>funct3=0</b><small>14:12</small></span><span class="bit operand w5"><b>dest</b><small>11:7</small></span><span class="bit fixed w7"><b>opcode</b><small>6:0</small></span></div></div>
    </div>

    <h2>All instruction encodings</h2>
    <div class="toolbar">
      <input id="search" type="search" placeholder="Search instruction, mnemonic, or description">
      <select id="format"><option value="">All formats</option><option>R3</option><option>R2</option><option>R1</option></select>
      <select id="category"><option value="">All categories</option>#{category_options}</select>
      <span id="visible"></span>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>#</th><th>Format</th><th>Instruction</th><th>Mnemonic / meaning</th><th>Bit encoding (31 → 0)</th><th>Mask</th><th>Match</th></tr></thead>
      <tbody id="rows">#{rows}</tbody>
    </table></div>
    <footer>Blue fields are fixed selectors; green fields are register operands. Category counts: #{escape.call(category_counts.sort.map { |k,v| "#{k}=#{v}" }.join(', '))}.</footer>
  </main>
  <script>
    const search = document.querySelector('#search'); const fmt = document.querySelector('#format');
    const category = document.querySelector('#category'); const rows = [...document.querySelectorAll('#rows tr')];
    const visible = document.querySelector('#visible');
    function filterRows() { const q=search.value.toLowerCase(); let count=0; rows.forEach(row => {
      const show=(!q || row.textContent.toLowerCase().includes(q)) && (!fmt.value || row.dataset.format===fmt.value)
        && (!category.value || row.dataset.category===category.value); row.classList.toggle('hidden', !show); if(show) count++; });
      visible.textContent = `${count} shown`; }
    [search,fmt,category].forEach(control => control.addEventListener('input', filterRows)); filterRows();
  </script></body></html>
HTML

if ARGV == ["--check"]
  current = File.exist?(output_path) ? File.read(output_path) : ""
  abort "INSTRUCTION_ENCODINGS.html is stale; run ruby scripts/generate-instruction-encoding-html.rb" unless current == html
  puts "checked HTML instruction encoding catalog: #{entries.length} entries are current"
elsif ARGV.empty?
  File.write(output_path, html)
  puts "wrote #{output_path} with #{entries.length} instruction encodings"
else
  abort "usage: #{$PROGRAM_NAME} [--check]"
end
