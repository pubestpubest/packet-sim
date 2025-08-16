import React, { useMemo, useState } from "react";

// Packet Diagram Studio (React + TS)
// Tabs for DNS, TCP, HTTP. Views: HEX & BITS only.
// - DNS: 12-byte header + Question builder (QNAME/QTYPE/QCLASS)
// - TCP: 20-byte header with SYN/ACK/etc flags
// - HTTP: Request builder showing CRLF bytes (0D 0A)
// No external CSS needed beyond Tailwind; 16-col grids use inline styles.

// ------------------------------ Types & Data ------------------------------

type Field = { name: string; startBit: number; length: number; hint?: string };
type Mode = "bits" | "hex";

type TypeOpt = { code: number; label: string };

const QTYPE_OPTS: TypeOpt[] = [
  { code: 1, label: "A (1)" },
  { code: 2, label: "NS (2)" },
  { code: 5, label: "CNAME (5)" },
  { code: 12, label: "PTR (12)" },
  { code: 15, label: "MX (15)" },
  { code: 16, label: "TXT (16)" },
  { code: 28, label: "AAAA (28)" },
];

const QCLASS_OPTS: TypeOpt[] = [
  { code: 1, label: "IN (1)" },
  { code: 3, label: "CH (3)" },
  { code: 4, label: "HS (4)" },
];

// DNS header fields (fixed 12-byte header = 96 bits)
const HEADER_FIELDS: Field[] = [
  { name: "ID", startBit: 0, length: 16, hint: "Identifier" },
  { name: "FLAGS", startBit: 16, length: 16, hint: "QR|Opcode|AA|TC|RD|RA|Z|RCODE" },
  { name: "QDCOUNT", startBit: 32, length: 16, hint: "# of Questions" },
  { name: "ANCOUNT", startBit: 48, length: 16, hint: "# of Answers" },
  { name: "NSCOUNT", startBit: 64, length: 16, hint: "# of Authority (NS)" },
  { name: "ARCOUNT", startBit: 80, length: 16, hint: "# of Additional" },
];

// TCP header fields (fixed 20-byte header = 160 bits)
const TCP_FIELDS: Field[] = [
  { name: "Source Port", startBit: 0, length: 16, hint: "Source port number" },
  { name: "Destination Port", startBit: 16, length: 16, hint: "Destination port number" },
  { name: "Sequence Number", startBit: 32, length: 32, hint: "Sequence number" },
  { name: "Acknowledgment Number", startBit: 64, length: 32, hint: "Acknowledgment number" },
  { name: "Data Offset", startBit: 96, length: 4, hint: "Header length in 32-bit words" },
  { name: "Reserved", startBit: 100, length: 3, hint: "Reserved bits (must be zero)" },
  { name: "NS", startBit: 103, length: 1, hint: "ECN-nonce concealment protection" },
  { name: "CWR", startBit: 104, length: 1, hint: "Congestion Window Reduced" },
  { name: "ECE", startBit: 105, length: 1, hint: "ECN-Echo" },
  { name: "URG", startBit: 106, length: 1, hint: "Urgent pointer field significant" },
  { name: "ACK", startBit: 107, length: 1, hint: "Acknowledgment field significant" },
  { name: "PSH", startBit: 108, length: 1, hint: "Push function" },
  { name: "RST", startBit: 109, length: 1, hint: "Reset the connection" },
  { name: "SYN", startBit: 110, length: 1, hint: "Synchronize sequence numbers" },
  { name: "FIN", startBit: 111, length: 1, hint: "No more data from sender" },
  { name: "Window", startBit: 112, length: 16, hint: "Window size" },
  { name: "Checksum", startBit: 128, length: 16, hint: "Header and data checksum" },
  { name: "Urgent Pointer", startBit: 144, length: 16, hint: "Points to urgent data" },
];

// Example base DNS header: query with RD=1, QDCOUNT=1
const INITIAL_HEADER = Uint8Array.from([
  0x1a, 0x33, // ID (changeable)
  0x01, 0x00, // FLAGS (QR=0, RD=1)
  0x00, 0x01, // QDCOUNT = 1
  0x00, 0x00, // ANCOUNT = 0
  0x00, 0x00, // NSCOUNT = 0
  0x00, 0x00, // ARCOUNT = 0
]);

// ------------------------------ Utils ------------------------------

const enc = new TextEncoder();

function toBitString(bytes: Uint8Array) {
  return Array.from(bytes).map((b) => b.toString(2).padStart(8, "0")).join("");
}
function byteToHex(b: number) { return b.toString(16).padStart(2, "0").toUpperCase(); }
function wordToHex(w: number) { return w.toString(16).padStart(4, "0").toUpperCase(); }
function u16be(b0: number, b1: number) { return (b0 << 8) | b1; }
function setU16be(bytes: Uint8Array, offset: number, value: number) { bytes[offset] = (value >> 8) & 0xff; bytes[offset + 1] = value & 0xff; }
function clampU16(x: number) { return Math.max(0, Math.min(0xffff, x)); }

function colorFor(name: string) { const seed = Array.from(name).reduce((a, c) => a + c.charCodeAt(0), 0); const hue = seed % 360; return `hsl(${hue}deg 70% 88% / 1)`; }

// FLAGS bit positions in DNS 16-bit word
const FLAG_BITS = { QR: 15, AA: 10, TC: 9, RD: 8, RA: 7 } as const;
function getFlag(word: number, bit: number) { return ((word >> bit) & 1) === 1; }
function setFlag(word: number, bit: number, v: boolean) { return v ? (word | (1 << bit)) : (word & ~(1 << bit)); }

// Build QNAME bytes from domain (no compression). Each label: len + bytes, then 0x00.
function qnameFromDomain(domain: string): Uint8Array {
  const labels = domain.trim().replace(/\.$/, "").split(".").filter(Boolean);
  const parts: number[] = [];
  for (const lab of labels) {
    const bytes = enc.encode(lab);
    if (bytes.length > 63) throw new Error("Label too long (max 63)");
    parts.push(bytes.length, ...Array.from(bytes));
  }
  parts.push(0x00); // root terminator
  return Uint8Array.from(parts);
}

function concatBytes(a: Uint8Array, b: Uint8Array) { const out = new Uint8Array(a.length + b.length); out.set(a, 0); out.set(b, a.length); return out; }

// 16-col grid helper (inline grid-template-columns)
function Grid16({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`grid ${className}`} style={{ gridTemplateColumns: "repeat(16, minmax(0, 1fr))" }}>
      {children}
    </div>
  );
}

// 32-col grid helper for TCP diagrams
function Grid32({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`grid ${className}`} style={{ gridTemplateColumns: "repeat(32, minmax(0, 1fr))" }}>
      {children}
    </div>
  );
}

// ------------------------------ Root Component ------------------------------

export default function PacketDiagramStudio() {
  const [mode, setMode] = useState<Mode>("hex");
  const [tab, setTab] = useState<"dns" | "tcp" | "http">("dns");
  return (
    <div className="mx-auto max-w-6xl p-4">
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Packet Diagram Studio</h1>
          <p className="text-slate-600">Switch between DNS, TCP, and HTTP. Views: HEX & BITS only.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="inline-flex overflow-hidden rounded-xl border border-slate-200">
            {(["dns", "tcp", "http"] as const).map((m) => (
              <button key={m} onClick={() => setTab(m)} className={"px-3 py-1.5 text-sm font-medium " + (tab === m ? "bg-slate-900 text-white" : "bg-white text-slate-700 hover:bg-slate-50")}>{m.toUpperCase()}</button>
            ))}
          </div>
          <div className="inline-flex overflow-hidden rounded-xl border border-slate-200">
            {(["bits", "hex"] as Mode[]).map((m) => (
              <button key={m} onClick={() => setMode(m)} className={"px-3 py-1.5 text-sm font-medium " + (mode === m ? "bg-slate-900 text-white" : "bg-white text-slate-700 hover:bg-slate-50")}>{m.toUpperCase()}</button>
            ))}
          </div>
        </div>
      </div>
      {tab === "dns" && <DNSView mode={mode} />}
      {tab === "tcp" && <TCPView mode={mode} />}
      {tab === "http" && <HTTPView mode={mode} />}
      <div className="mt-6 rounded-2xl border border-slate-200 p-4">
        <h3 className="mb-2 text-base font-semibold">Legend</h3>
        <ul className="list-inside list-disc text-sm text-slate-700">
          <li>Two hex digits = 1 byte. Four hex digits = 16 bits (one RFC-style row).</li>
          <li>Big-endian (network order) for multi-byte numbers (DNS/TCP headers).</li>
          <li>HTTP is text: CRLF = <span className="font-mono">0D 0A</span>.</li>
        </ul>
      </div>
    </div>
  );
}

// ============================== DNS VIEW ==============================
function DNSView({ mode }: { mode: Mode }) {
  const [header, setHeader] = useState<Uint8Array>(Uint8Array.from(INITIAL_HEADER));
  const id = useMemo(() => u16be(header[0], header[1]), [header]);
  const flagsWord = useMemo(() => u16be(header[2], header[3]), [header]);
  const qd = useMemo(() => u16be(header[4], header[5]), [header]);
  const an = useMemo(() => u16be(header[6], header[7]), [header]);
  const ns = useMemo(() => u16be(header[8], header[9]), [header]);
  const ar = useMemo(() => u16be(header[10], header[11]), [header]);

  // Question controls
  const [domain, setDomain] = useState<string>("www.example.com");
  const [qtype, setQtype] = useState<number>(1);
  const [qclass, setQclass] = useState<number>(1);

  const qnameBytes = useMemo(() => { try { return qnameFromDomain(domain); } catch { return new Uint8Array([0x00]); } }, [domain]);
  const qtail = useMemo(() => Uint8Array.from([(qtype >> 8) & 0xff, qtype & 0xff, (qclass >> 8) & 0xff, qclass & 0xff]), [qtype, qclass]);
  const question = useMemo(() => concatBytes(qnameBytes, qtail), [qnameBytes, qtail]);
  const message = useMemo(() => concatBytes(header, question), [header, question]);



  const toggleFlag = (key: keyof typeof FLAG_BITS) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const nw = setFlag(flagsWord, FLAG_BITS[key], e.target.checked); const next = Uint8Array.from(header); setU16be(next, 2, nw); setHeader(next);
  };
  const setCount = (which: "QD" | "AN" | "NS" | "AR") => (e: React.ChangeEvent<HTMLInputElement>) => { const v = clampU16(parseInt(e.target.value || "0", 10)); const next = Uint8Array.from(header); const off = { QD: 4, AN: 6, NS: 8, AR: 10 }[which]; setU16be(next, off, v); setHeader(next); };
  const setIdField = (e: React.ChangeEvent<HTMLInputElement>) => { const v = clampU16(parseInt(e.target.value || "0", 10)); const next = Uint8Array.from(header); setU16be(next, 0, v); setHeader(next); };

  function RowBits({ row }: { row: number }) {
    const b0 = header[row * 2]; const b1 = header[row * 2 + 1]; const toBits = (x: number) => x.toString(2).padStart(8, "0");
    return (
      <Grid16 className="gap-1 font-mono text-[10px]">
        {toBits(b0).split("").map((bit, i) => (<div key={i} className="rounded bg-slate-100 px-1 py-[2px] text-center">{bit}</div>))}
        {toBits(b1).split("").map((bit, i) => (<div key={i+8} className="rounded bg-slate-100 px-1 py-[2px] text-center">{bit}</div>))}
      </Grid16>
    );
  }
  function RowHex({ row }: { row: number }) { const b0 = header[row * 2]; const b1 = header[row * 2 + 1]; return (<div className="grid grid-cols-2 gap-2 text-xs font-mono"><div className="rounded-md bg-slate-100 px-2 py-1 text-center">{byteToHex(b0)}</div><div className="rounded-md bg-slate-100 px-2 py-1 text-center">{byteToHex(b1)}</div></div>); }

  const hex = (b: Uint8Array) => Array.from(b).map(byteToHex).join(" ");
  const bits = (b: Uint8Array) => toBitString(b);

  return (
    <div>
      <h2 className="mb-2 text-lg font-semibold">DNS — Header + Question</h2>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 p-4">
          <h3 className="mb-2 font-semibold">Header Fields</h3>
          <div className="space-y-3 text-sm">
            <label className="block"><div className="mb-1 text-slate-600">ID</div><input type="number" value={id} min={0} max={65535} onChange={setIdField} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
            <div className="rounded-xl bg-slate-50 p-3">
              <div className="mb-1 font-medium">FLAGS</div>
              <div className="mb-2 grid grid-cols-2 gap-2">
                <label className="flex items-center gap-2"><input type="checkbox" checked={getFlag(flagsWord, FLAG_BITS.QR)} onChange={toggleFlag("QR")} /><span>QR</span></label>
                <label className="flex items-center gap-2"><input type="checkbox" checked={getFlag(flagsWord, FLAG_BITS.AA)} onChange={toggleFlag("AA")} /><span>AA</span></label>
                <label className="flex items-center gap-2"><input type="checkbox" checked={getFlag(flagsWord, FLAG_BITS.TC)} onChange={toggleFlag("TC")} /><span>TC</span></label>
                <label className="flex items-center gap-2"><input type="checkbox" checked={getFlag(flagsWord, FLAG_BITS.RD)} onChange={toggleFlag("RD")} /><span>RD</span></label>
                <label className="flex items-center gap-2"><input type="checkbox" checked={getFlag(flagsWord, FLAG_BITS.RA)} onChange={toggleFlag("RA")} /><span>RA</span></label>
              </div>
              <div className="text-xs text-slate-600">Word: 0x{wordToHex(flagsWord)}</div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="block"><div className="mb-1 text-slate-600">QDCOUNT</div><input type="number" value={qd} min={0} max={65535} onChange={setCount("QD")} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
              <label className="block"><div className="mb-1 text-slate-600">ANCOUNT</div><input type="number" value={an} min={0} max={65535} onChange={setCount("AN")} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
              <label className="block"><div className="mb-1 text-slate-600">NSCOUNT</div><input type="number" value={ns} min={0} max={65535} onChange={setCount("NS")} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
              <label className="block"><div className="mb-1 text-slate-600">ARCOUNT</div><input type="number" value={ar} min={0} max={65535} onChange={setCount("AR")} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
            </div>
          </div>
        </div>
        <div className="rounded-2xl border border-slate-200 p-4 md:col-span-2">
          <h3 className="mb-2 font-semibold">Header Diagram (12 bytes)</h3>
          <div className="mb-3 overflow-hidden rounded-xl border border-slate-200">
            <Grid16 className="bg-slate-50 px-2 py-1 text-[10px] font-mono text-slate-600">
              {Array.from({ length: 16 }, (_, i) => (<div key={i} className="text-center">{i.toString(16).toUpperCase()}</div>))}
            </Grid16>
            {Array.from({ length: 6 }, (_, r) => (
              <div key={r} className="border-t border-slate-200 px-2 py-2">
                <Grid16 className="mb-1 gap-[2px] text-[10px]">
                  {(() => { const rowStart = r * 16; const rowEnd = rowStart + 16; type Segment = { len: number; label?: string; color?: string }; type Piece = { start: number; end: number; field: Field }; const pieces: Piece[] = []; for (const f of HEADER_FIELDS) { const fStart = f.startBit; const fEnd = f.startBit + f.length; const s = Math.max(rowStart, fStart); const e = Math.min(rowEnd, fEnd); if (e > s) pieces.push({ start: s, end: e, field: f }); } pieces.sort((a,b)=>a.start-b.start); const segs: Segment[] = []; let cursor = rowStart; for (const p of pieces) { if (p.start > cursor) segs.push({ len: p.start - cursor }); const firstInRow = p.start === Math.max(rowStart, p.field.startBit); segs.push({ len: p.end - p.start, label: firstInRow ? p.field.name : undefined, color: colorFor(p.field.name) }); cursor = p.end; } if (cursor < rowEnd) segs.push({ len: rowEnd - cursor }); return segs; })().map((seg, i) => (
                    <div key={i} className="relative" style={{ gridColumn: `span ${seg.len} / span ${seg.len}` }}>
                      <div className="h-6 w-full rounded-md border border-slate-300" style={{ background: seg.color ?? "#fff" }} />
                      {seg.label && (<div className="pointer-events-none absolute inset-0 flex items-center justify-center text-[10px] font-semibold text-slate-700">{seg.label}</div>)}
                    </div>
                  ))}
                </Grid16>
                {mode === "hex" ? <RowHex row={r} /> : <RowBits row={r} />}
              </div>
            ))}
          </div>
          <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
            <div className="rounded-lg bg-slate-50 p-3 font-mono text-xs"><div className="mb-1 text-[11px] font-semibold text-slate-600">HEX (12 bytes)</div><div className="break-all">{hex(header)}</div></div>
            <div className="rounded-lg bg-slate-50 p-3 font-mono text-[10px]"><div className="mb-1 text-[11px] font-semibold text-slate-600">BITS (96 bits)</div><div className="break-all leading-4">{bits(header)}</div></div>
          </div>
        </div>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 p-4">
          <h3 className="mb-2 font-semibold">Question Builder</h3>
          <label className="block text-sm"><div className="mb-1 text-slate-600">Domain</div><input value={domain} onChange={(e) => setDomain(e.target.value)} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
          <div className="mt-2 grid grid-cols-2 gap-2 text-sm">
            <label className="block"><div className="mb-1 text-slate-600">QTYPE</div><select value={qtype} onChange={(e) => setQtype(parseInt(e.target.value,10))} className="w-full rounded-lg border border-slate-300 px-2 py-1">{QTYPE_OPTS.map(o => <option key={o.code} value={o.code}>{o.label}</option>)}</select></label>
            <label className="block"><div className="mb-1 text-slate-600">QCLASS</div><select value={qclass} onChange={(e) => setQclass(parseInt(e.target.value,10))} className="w-full rounded-lg border border-slate-300 px-2 py-1">{QCLASS_OPTS.map(o => <option key={o.code} value={o.code}>{o.label}</option>)}</select></label>
          </div>
          <div className="mt-2 text-xs text-slate-600">QNAME bytes: {qnameBytes.length} • Question bytes: {question.length}</div>
        </div>
        <div className="rounded-2xl border border-slate-200 p-4 md:col-span-2">
          <h3 className="mb-2 font-semibold">Question Bytes</h3>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            <div className="rounded-lg bg-slate-50 p-3 font-mono text-xs"><div className="mb-1 text-[11px] font-semibold text-slate-600">HEX</div><div className="break-all">{hex(question)}</div></div>
            <div className="rounded-lg bg-slate-50 p-3 font-mono text-[10px]"><div className="mb-1 text-[11px] font-semibold text-slate-600">BITS</div><div className="break-all leading-4">{bits(question)}</div></div>
          </div>
        </div>
      </div>

      <div className="mt-6 rounded-2xl border border-slate-200 p-4">
        <h3 className="mb-2 font-semibold">Combined DNS Message</h3>
        <div className="text-sm text-slate-600 mb-2">Total: {message.length} bytes</div>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          <div className="rounded-lg bg-slate-50 p-3 font-mono text-xs"><div className="mb-1 text-[11px] font-semibold text-slate-600">HEX</div><div className="break-all">{hex(message)}</div></div>
          <div className="rounded-lg bg-slate-50 p-3 font-mono text-[10px]"><div className="mb-1 text-[11px] font-semibold text-slate-600">BITS</div><div className="break-all leading-4">{bits(message)}</div></div>
        </div>
      </div>
    </div>
  );
}

// ============================== TCP VIEW ==============================
function TCPView({ mode }: { mode: Mode }) {
  // Minimal 20-byte TCP header (no options)
  const [src, setSrc] = useState(12345);
  const [dst, setDst] = useState(80);
  const [seq, setSeq] = useState(0);
  const [ack, setAck] = useState(0);
  const [flags, setFlags] = useState({ NS:false, CWR:false, ECE:false, URG:false, ACK:false, PSH:false, RST:false, SYN:true, FIN:false });
  const [win, setWin] = useState(65535);
  const dataOffset = 5; // 5 * 4 = 20 bytes

  function buildHeader(): Uint8Array {
    const b = new Uint8Array(20);
    // src/dst ports
    b[0] = (src >> 8) & 0xff; b[1] = src & 0xff; b[2] = (dst >> 8) & 0xff; b[3] = dst & 0xff;
    // seq
    b[4] = (seq >>> 24) & 0xff; b[5] = (seq >>> 16) & 0xff; b[6] = (seq >>> 8) & 0xff; b[7] = seq & 0xff;
    // ack
    b[8] = (ack >>> 24) & 0xff; b[9] = (ack >>> 16) & 0xff; b[10] = (ack >>> 8) & 0xff; b[11] = ack & 0xff;
    // data offset/reserved/NS
    let byte12 = (dataOffset & 0xf) << 4; // high nibble
    if (flags.NS) byte12 |= 1; // LSB
    b[12] = byte12;
    // flags byte
    let f = 0;
    if (flags.CWR) f |= 1 << 7;
    if (flags.ECE) f |= 1 << 6;
    if (flags.URG) f |= 1 << 5;
    if (flags.ACK) f |= 1 << 4;
    if (flags.PSH) f |= 1 << 3;
    if (flags.RST) f |= 1 << 2;
    if (flags.SYN) f |= 1 << 1;
    if (flags.FIN) f |= 1 << 0;
    b[13] = f;
    // window
    b[14] = (win >> 8) & 0xff; b[15] = win & 0xff;
    // checksum/urgent pointer (zero here; real checksum needs pseudo-header)
    b[16] = 0; b[17] = 0; b[18] = 0; b[19] = 0;
    return b;
  }

  const header = useMemo(buildHeader, [src, dst, seq, ack, flags, win]);

  function TCPRowBits({ row }: { row: number }) {
    const b0 = header[row * 4]; const b1 = header[row * 4 + 1]; const b2 = header[row * 4 + 2]; const b3 = header[row * 4 + 3];
    const toBits = (x: number) => x.toString(2).padStart(8, "0");
    return (
      <Grid32 className="gap-1 font-mono text-[10px]">
        {toBits(b0).split("").map((bit, i) => (<div key={i} className="rounded bg-slate-100 px-1 py-[2px] text-center">{bit}</div>))}
        {toBits(b1).split("").map((bit, i) => (<div key={i+8} className="rounded bg-slate-100 px-1 py-[2px] text-center">{bit}</div>))}
        {toBits(b2).split("").map((bit, i) => (<div key={i+16} className="rounded bg-slate-100 px-1 py-[2px] text-center">{bit}</div>))}
        {toBits(b3).split("").map((bit, i) => (<div key={i+24} className="rounded bg-slate-100 px-1 py-[2px] text-center">{bit}</div>))}
      </Grid32>
    );
  }
  
  function TCPRowHex({ row }: { row: number }) {
    const b0 = header[row * 4]; const b1 = header[row * 4 + 1]; const b2 = header[row * 4 + 2]; const b3 = header[row * 4 + 3];
    return (
      <div className="grid grid-cols-4 gap-2 text-xs font-mono">
        <div className="rounded-md bg-slate-100 px-2 py-1 text-center">{byteToHex(b0)}</div>
        <div className="rounded-md bg-slate-100 px-2 py-1 text-center">{byteToHex(b1)}</div>
        <div className="rounded-md bg-slate-100 px-2 py-1 text-center">{byteToHex(b2)}</div>
        <div className="rounded-md bg-slate-100 px-2 py-1 text-center">{byteToHex(b3)}</div>
      </div>
    );
  }

  const hex = (b: Uint8Array) => Array.from(b).map(byteToHex).join(" ");
  const bits = (b: Uint8Array) => toBitString(b);

  return (
    <div>
      <h2 className="mb-2 text-lg font-semibold">TCP — 20-byte Header</h2>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 p-4 text-sm">
          <div className="grid grid-cols-2 gap-2">
            <label className="block"><div className="mb-1 text-slate-600">Src Port</div><input type="number" value={src} onChange={(e)=>setSrc(parseInt(e.target.value||"0",10))} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
            <label className="block"><div className="mb-1 text-slate-600">Dst Port</div><input type="number" value={dst} onChange={(e)=>setDst(parseInt(e.target.value||"0",10))} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
            <label className="col-span-2 block"><div className="mb-1 text-slate-600">Seq</div><input type="number" value={seq} onChange={(e)=>setSeq(parseInt(e.target.value||"0",10))} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
            <label className="col-span-2 block"><div className="mb-1 text-slate-600">Ack</div><input type="number" value={ack} onChange={(e)=>setAck(parseInt(e.target.value||"0",10))} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
          </div>
          <div className="mt-3 rounded-xl bg-slate-50 p-3">
            <div className="mb-1 font-medium">Flags</div>
            <div className="grid grid-cols-3 gap-2">
              {(["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"] as const).map(k => (
                <label key={k} className="flex items-center gap-2"><input type="checkbox" checked={flags[k]} onChange={(e)=>setFlags({...flags,[k]:e.target.checked})}/><span>{k}</span></label>
              ))}
            </div>
          </div>
          <label className="mt-3 block"><div className="mb-1 text-slate-600">Window</div><input type="number" value={win} onChange={(e)=>setWin(parseInt(e.target.value||"0",10))} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
        </div>
        <div className="rounded-2xl border border-slate-200 p-4 md:col-span-2">
          <h3 className="mb-2 font-semibold">TCP Header Diagram (20 bytes, 32-bit rows)</h3>
          <div className="mb-3 overflow-hidden rounded-xl border border-slate-200">
            <Grid32 className="bg-slate-50 px-2 py-1 text-[10px] font-mono text-slate-600">
              {Array.from({ length: 32 }, (_, i) => (<div key={i} className="text-center">{i.toString(16).toUpperCase()}</div>))}
            </Grid32>
            {Array.from({ length: 5 }, (_, r) => (
              <div key={r} className="border-t border-slate-200 px-2 py-2">
                <Grid32 className="mb-1 gap-[2px] text-[10px]">
                  {(() => {
                    const rowStart = r * 32;
                    const rowEnd = rowStart + 32;
                    type Segment = { len: number; label?: string; color?: string };
                    type Piece = { start: number; end: number; field: Field };
                    const pieces: Piece[] = [];
                    for (const f of TCP_FIELDS) {
                      const fStart = f.startBit;
                      const fEnd = f.startBit + f.length;
                      const s = Math.max(rowStart, fStart);
                      const e = Math.min(rowEnd, fEnd);
                      if (e > s) pieces.push({ start: s, end: e, field: f });
                    }
                    pieces.sort((a,b)=>a.start-b.start);
                    const segs: Segment[] = [];
                    let cursor = rowStart;
                    for (const p of pieces) {
                      if (p.start > cursor) segs.push({ len: p.start - cursor });
                      const firstInRow = p.start === Math.max(rowStart, p.field.startBit);
                      segs.push({ 
                        len: p.end - p.start, 
                        label: firstInRow ? p.field.name : undefined, 
                        color: colorFor(p.field.name) 
                      });
                      cursor = p.end;
                    }
                    if (cursor < rowEnd) segs.push({ len: rowEnd - cursor });
                    return segs;
                  })().map((seg, i) => (
                    <div key={i} className="relative" style={{ gridColumn: `span ${seg.len} / span ${seg.len}` }}>
                      <div className="h-6 w-full rounded-md border border-slate-300" style={{ background: seg.color ?? "#fff" }} />
                      {seg.label && (<div className="pointer-events-none absolute inset-0 flex items-center justify-center text-[10px] font-semibold text-slate-700">{seg.label}</div>)}
                    </div>
                  ))}
                </Grid32>
                {mode === "hex" ? <TCPRowHex row={r} /> : <TCPRowBits row={r} />}
              </div>
            ))}
          </div>
          <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
            <div className="rounded-lg bg-slate-50 p-3 font-mono text-xs"><div className="mb-1 text-[11px] font-semibold text-slate-600">HEX (20 bytes)</div><div className="break-all">{hex(header)}</div></div>
            <div className="rounded-lg bg-slate-50 p-3 font-mono text-[10px]"><div className="mb-1 text-[11px] font-semibold text-slate-600">BITS (160 bits)</div><div className="break-all leading-4">{bits(header)}</div></div>
          </div>
          <div className="mt-2 text-xs text-slate-600">Data Offset fixed at 5 (no options). Toggle SYN/ACK for handshake patterns.</div>
        </div>
      </div>
    </div>
  );
}

// ============================== HTTP VIEW ==============================
function HTTPView({ mode }: { mode: Mode }) {
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/");
  const [host, setHost] = useState("example.com");
  const [extra, setExtra] = useState("");
  const [body, setBody] = useState("");

  const reqStr = useMemo(() => {
    const headers: string[] = [`Host: ${host}`];
    if (extra.trim()) headers.push(extra.trim());
    return `${method} ${path} HTTP/1.1\r\n` +
           headers.join("\r\n") + "\r\n\r\n" +
           body;
  }, [method, path, host, extra, body]);

  const reqBytes = useMemo(() => new TextEncoder().encode(reqStr), [reqStr]);

  function HTTPBlockRow({ tokens }: { tokens: { label: string; len: number; color?: string }[] }) {
    const totalLen = tokens.reduce((sum, t) => sum + t.len, 0);
    return (
      <div className="flex rounded-lg border border-slate-300 overflow-hidden">
        {tokens.map((token, i) => (
          <div 
            key={i} 
            className="relative border-r border-slate-300 last:border-r-0 min-h-[2rem] flex items-center justify-center text-xs font-semibold text-slate-700"
            style={{ 
              flexGrow: token.len,
              backgroundColor: token.color || colorFor(token.label),
              minWidth: `${Math.max(20, (token.len / totalLen) * 100)}px`
            }}
          >
            <span className="px-1 text-center">{token.label}</span>
          </div>
        ))}
      </div>
    );
  }

  const requestLineTokens = [
    { label: method, len: enc.encode(method).length },
    { label: "SP", len: 1 },
    { label: path, len: enc.encode(path).length },
    { label: "SP", len: 1 },
    { label: "HTTP/1.1", len: 8 },
    { label: "CRLF", len: 2 },
  ];

  const hostHeaderTokens = [
    { label: "Host", len: 4 },
    { label: ": ", len: 2 },
    { label: host, len: enc.encode(host).length },
    { label: "CRLF", len: 2 },
  ];

  const extraHeaderTokens = extra.trim() ? [
    { label: extra.trim().split(':')[0] || 'Header', len: enc.encode(extra.trim().split(':')[0] || 'Header').length },
    { label: ": ", len: 2 },
    { label: extra.trim().split(':').slice(1).join(':').trim() || 'Value', len: enc.encode(extra.trim().split(':').slice(1).join(':').trim() || 'Value').length },
    { label: "CRLF", len: 2 },
  ] : [];

  const blankLineTokens = [{ label: "CRLF (Blank Line)", len: 2 }];
  
  const bodyTokens = body ? [{ label: "Message Body", len: enc.encode(body).length }] : [];

  const hex = (b: Uint8Array) => Array.from(b).map(byteToHex).join(" ");
  const bits = (b: Uint8Array) => toBitString(b);

  return (
    <div>
      <h2 className="mb-2 text-lg font-semibold">HTTP/1.1 — Request Builder</h2>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 p-4 text-sm">
          <div className="grid grid-cols-2 gap-2">
            <label className="block col-span-1"><div className="mb-1 text-slate-600">Method</div><select value={method} onChange={(e)=>setMethod(e.target.value)} className="w-full rounded-lg border border-slate-300 px-2 py-1"><option>GET</option><option>POST</option><option>HEAD</option></select></label>
            <label className="block col-span-1"><div className="mb-1 text-slate-600">Path</div><input value={path} onChange={(e)=>setPath(e.target.value)} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
          </div>
          <label className="block mt-2"><div className="mb-1 text-slate-600">Host</div><input value={host} onChange={(e)=>setHost(e.target.value)} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
          <label className="block mt-2"><div className="mb-1 text-slate-600">Extra header (optional)</div><input placeholder="User-Agent: demo" value={extra} onChange={(e)=>setExtra(e.target.value)} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
          <label className="block mt-2"><div className="mb-1 text-slate-600">Message Body (optional)</div><textarea rows={3} placeholder="Request body content..." value={body} onChange={(e)=>setBody(e.target.value)} className="w-full rounded-lg border border-slate-300 px-2 py-1"/></label>
          <div className="mt-2 text-xs text-slate-600">Lines end with CRLF <span className="font-mono">0D 0A</span>. Headers separated from body by blank line.</div>
        </div>
        <div className="rounded-2xl border border-slate-200 p-4 md:col-span-2">
          <h3 className="mb-2 font-semibold">HTTP Request Structure</h3>
          <div className="space-y-2 mb-4">
            <div>
              <div className="text-xs font-medium text-slate-600 mb-1">Request Line</div>
              <HTTPBlockRow tokens={requestLineTokens} />
            </div>
            <div>
              <div className="text-xs font-medium text-slate-600 mb-1">Host Header</div>
              <HTTPBlockRow tokens={hostHeaderTokens} />
            </div>
            {extraHeaderTokens.length > 0 && (
              <div>
                <div className="text-xs font-medium text-slate-600 mb-1">Extra Header</div>
                <HTTPBlockRow tokens={extraHeaderTokens} />
              </div>
            )}
            <div>
              <div className="text-xs font-medium text-slate-600 mb-1">Blank Line</div>
              <HTTPBlockRow tokens={blankLineTokens} />
            </div>
            {bodyTokens.length > 0 && (
              <div>
                <div className="text-xs font-medium text-slate-600 mb-1">Message Body</div>
                <HTTPBlockRow tokens={bodyTokens} />
              </div>
            )}
          </div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            <div className="rounded-lg bg-slate-50 p-3 font-mono text-xs"><div className="mb-1 text-[11px] font-semibold text-slate-600">{mode.toUpperCase()} ({reqBytes.length} bytes)</div><div className="break-all">{mode === "hex" ? hex(reqBytes) : bits(reqBytes)}</div></div>
            <div className="rounded-lg bg-slate-50 p-3 font-mono text-xs"><div className="mb-1 text-[11px] font-semibold text-slate-600">Request String</div><div className="break-all whitespace-pre-wrap text-slate-600">{reqStr.replace(/\r\n/g, '↵\n')}</div></div>
          </div>
          <div className="mt-2 text-xs text-slate-600">CRLF appears as 0D 0A in hex. Notice the blank line (double CRLF) separating headers from body.</div>
        </div>
      </div>
    </div>
  );
}
