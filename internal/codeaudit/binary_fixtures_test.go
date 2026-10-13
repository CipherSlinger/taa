package codeaudit

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"

	"debug/elf"
)

// elfSpec describes the ELF the fixture builder writes.
type elfSpec struct {
	// imports become STB_GLOBAL, SHN_UNDEF entries in .dynsym: the symbols the
	// binary imports from its libraries. That is the evidence a stripped binary
	// still carries, which is why the fixture is built around them.
	imports []string
	// needed become DT_NEEDED entries in .dynamic.
	needed []string
	// text is the content of .text, and textExec decides whether .text carries
	// SHF_EXECINSTR - which is what makes its entropy an executable-section
	// verdict rather than a section summary.
	text     []byte
	textExec bool
	// text2, when non-nil, adds a second section named .init, and text2Exec
	// decides whether it carries SHF_EXECINSTR. Two executable sections are the
	// case where the verdict has to be produced per section rather than once per
	// file: .text may measure clean while .init is packed, and a fixture with one
	// executable section cannot tell a loop over sections from a single check on
	// the first match.
	text2     []byte
	text2Exec bool
	// overrun, when non-zero, adds that many bytes to .text's declared sh_size
	// without writing them. The section header then claims more than the file
	// holds, which is the case the extractor has to catch by comparing the bytes
	// it actually read against the declared size rather than by trusting the
	// header.
	overrun uint64
	// noSections, when true, writes no section header table at all: e_shoff,
	// e_shnum and e_shstrndx are all zero. debug/elf accepts this - it rejects
	// only shoff == 0 with shnum != 0 - and yields zero sections, which is
	// exactly the file the extractor's fail-open used to let through.
	noSections bool
	// soname, when non-empty, adds a DT_SONAME entry to .dynamic. It must be
	// expressible because collectELF calls DynString(elf.DT_SONAME).
	soname string
	// interp, when non-empty, adds a PT_INTERP program header whose file range
	// holds the NUL-terminated interpreter path. It must be expressible because
	// collectELF walks ef.Progs looking for PT_INTERP.
	interp string
	// stripped, when true, omits the SHT_DYNSYM section header entirely. That is
	// what makes debug/elf return elf.ErrNoSymbols: SectionByType(SHT_DYNSYM)
	// returns nil only when no section carries that type. A .dynsym that exists
	// but holds only the 24-byte null entry is a different case: it yields an
	// empty symbol list and a nil error.
	stripped bool
	// zeroDynsym, when true, keeps the SHT_DYNSYM section header but writes its
	// sh_size as 0: a symbol table that is present in the header table yet
	// declares no bytes. It is the shape that makes debug/elf's 64-bit symbol
	// reader panic, because getSymbols64 rejects only lengths that are not a
	// multiple of 24 and then slices data[24:] - and zero is a multiple of 24.
	// Neither of the other two shapes reaches that: a stripped file omits the
	// section, and a normal empty table carries the 24-byte reserved entry. So
	// the crash needs its own switch rather than a reuse of `stripped`.
	zeroDynsym bool
	// zdebugDynsym, when true, names the SHT_DYNSYM section ".zdebug_dynsym" and
	// gives it a 12-byte ".zdebug" body: the "ZLIB" magic followed by a big-endian
	// uncompressed size of 0. debug/elf reads that header when the section is
	// opened, not when the file is parsed, and rewrites Section.Size from it - so
	// the on-disk sh_size stays an ordinary nonzero value while the data the
	// symbol reader receives is empty. That is the same empty buffer zeroDynsym
	// produces, by a route no size check on the header can see. The section's
	// sh_link still points at .dynstr, because the reader loads the string table
	// before it slices the symbol data.
	zdebugDynsym bool
	// shortDynsym, when true, gives the SHT_DYNSYM section a body shorter than one
	// 24-byte entry - eight bytes here - while leaving its name and sh_size
	// ordinary. It is the boundary between the two shapes above and the well-formed
	// table: the reader accepts the length, fails the multiple-of test and returns
	// the format error, so collectELF must fail the scan closed. A guard written as
	// a length range (len(data) < entrySize) would skip this table instead, which
	// is a fail-open - the table is malformed, not empty - and this is the fixture
	// that tells the two guards apart.
	shortDynsym bool
}

// elfFixtureBytes builds a minimal but well-formed ELF64 little-endian shared
// object with exactly the sections the extractor reads: .text, .init, .dynstr,
// .dynsym, .dynamic and .shstrtab, and (optionally) one PT_INTERP program header.
//
// It is built by hand rather than compiled, and committed as bytes rather than
// as a binary. A `go build` fixture cannot carry a dynamic symbol table without
// cgo, which the production image does not have; a committed binary fixture
// would be an opaque blob whose contents a reader cannot check against the
// assertions. Building it here pins the input to the layout the reader is
// supposed to understand, so a test failure names the field that moved.
//
// The layout follows the ELF64 spec, which debug/elf reads field by field:
//
//	ELF header            64 bytes
//	program header table  only when interp != "": one 56-byte Elf64_Phdr at offset 64
//	interpreter path      only when interp != "": NUL-terminated bytes
//	.text                 spec.text
//	.init                 spec.text2 (nothing written when nil)
//	.dynstr               a leading NUL, then each name once, NUL-terminated
//	.dynsym               24-byte entries; entry 0 is the null symbol (a zeroed
//	                      header slot when stripped)
//	.dynamic              16-byte entries; DT_NEEDED..., [DT_SONAME], then DT_NULL
//	.shstrtab             section names
//	section headers       64 bytes each, 7 of them (index 0 is the required SHT_NULL)
//
// The section indices are fixed (see the sec* constants) rather than computed
// from which sections a spec asks for, so e_shstrndx is the same number for
// every fixture. A stripped file leaves its .dynsym slot as a zeroed SHT_NULL
// header instead of shifting the ones after it: an unnamed zero-size section is
// inert to both this extractor and debug/elf's SectionByType, and the fixed
// index is what keeps e_shstrndx from having to be recomputed per fixture.
//
// Two layout hazards are worth stating because the failure mode is a crash
// rather than a test failure, and they are the shapes this builder can produce
// on purpose with zeroDynsym and zdebugDynsym. debug/elf slices off the first
// symbol entry unconditionally after a length check that only rejects sizes not
// a multiple of the entry size, so a SHT_DYNSYM that yields an empty buffer
// panics with "slice bounds out of range [24:0]". That empty buffer is produced
// by sh_size == 0, and also by a section named ".zdebug..." with a ZLIB header
// whose declared size is 0, because opening the section rewrites its size. A
// plain .dynsym must therefore always carry at least the 24-byte null entry.
// shortDynsym sits on the other side of that same length check: a body that is
// not a multiple of the entry size is rejected with a format error rather than
// sliced, so holding it back would be a fail-open, not a fix.
func elfFixtureBytes(t *testing.T, spec elfSpec) []byte {
	t.Helper()

	const (
		ehSize     = 64
		phEntSize  = 56 // Elf64_Phdr: 2 uint32 + 6 uint64
		shEntSize  = 64
		symEntSize = 24
		dynEntSize = 16
		// Section indices. shNum counts the SHT_NULL entry at index 0.
		secText    = 1
		secInit    = 2
		secDynstr  = 3
		secDynsym  = 4
		secDynamic = 5
		secShstr   = 6
		shNum      = 7
	)
	le := binary.LittleEndian
	align8 := func(n int) int { return (n + 7) &^ 7 }

	// .dynstr. Offsets are recorded as the table is built because both .dynsym
	// and .dynamic index into it.
	dynstr := []byte{0}
	nameAt := map[string]uint32{}
	intern := func(s string) uint32 {
		if off, ok := nameAt[s]; ok {
			return off
		}
		off := uint32(len(dynstr))
		dynstr = append(dynstr, s...)
		dynstr = append(dynstr, 0)
		nameAt[s] = off
		return off
	}
	var importOffsets []uint32
	if !spec.stripped {
		importOffsets = make([]uint32, len(spec.imports))
		for i, n := range spec.imports {
			importOffsets[i] = intern(n)
		}
	}
	neededOffsets := make([]uint32, len(spec.needed))
	for i, n := range spec.needed {
		neededOffsets[i] = intern(n)
	}
	var sonameOff uint32
	if spec.soname != "" {
		sonameOff = intern(spec.soname)
	}

	// .dynsym. Entry zero is the reserved null symbol; getSymbols64 skips it, so
	// the imports start at entry one. A stripped file has no .dynsym at all, and
	// the .zdebug shape carries the decompression header instead of symbols, while
	// shortDynsym carries a body too short to hold even the null entry.
	var dynsym []byte
	if !spec.stripped {
		switch {
		case spec.zdebugDynsym:
			// A .zdebug header: "ZLIB" and a big-endian uncompressed size. The size
			// here is 0, which is what open-time parsing turns into an empty read.
			dynsym = make([]byte, symEntSize*2)
			copy(dynsym[0:4], "ZLIB")
		case spec.shortDynsym:
			// A body under one entry wide. It is written verbatim with sh_size == 8,
			// so every header the file parser sees is ordinary; only the length the
			// symbol reader tests rejects it.
			dynsym = make([]byte, 8)
		default:
			dynsym = make([]byte, symEntSize*(len(spec.imports)+1))
			for i, off := range importOffsets {
				e := dynsym[symEntSize*(i+1):]
				le.PutUint32(e[0:4], off)
				e[4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)
				e[5] = 0
				le.PutUint16(e[6:8], uint16(elf.SHN_UNDEF))
				// st_value stays zero: an imported symbol has no address in this file,
				// which is exactly why a symbol finding carries no byte offset.
				le.PutUint64(e[8:16], 0)
				le.PutUint64(e[16:24], 0)
			}
		}
	}

	// .dynamic: one DT_NEEDED per library, an optional DT_SONAME, then DT_NULL.
	nDyn := len(spec.needed)
	if spec.soname != "" {
		nDyn++
	}
	dynamic := make([]byte, dynEntSize*(nDyn+1))
	di := 0
	for _, off := range neededOffsets {
		e := dynamic[dynEntSize*di:]
		le.PutUint64(e[0:8], uint64(elf.DT_NEEDED))
		le.PutUint64(e[8:16], uint64(off))
		di++
	}
	if spec.soname != "" {
		e := dynamic[dynEntSize*di:]
		le.PutUint64(e[0:8], uint64(elf.DT_SONAME))
		le.PutUint64(e[8:16], uint64(sonameOff))
		di++
	}
	// The DT_NULL terminator is the zeroed final entry written by make above.

	// .shstrtab: the section names, indexed by offset.
	shstrtab := []byte{0}
	shName := func(s string) uint32 {
		off := uint32(len(shstrtab))
		shstrtab = append(shstrtab, s...)
		shstrtab = append(shstrtab, 0)
		return off
	}
	nText := shName(".text")
	nInit := shName(".init")
	nDynstr := shName(".dynstr")
	dynsymName := ".dynsym"
	if spec.zdebugDynsym {
		dynsymName = ".zdebug_dynsym"
	}
	nDynsym := shName(dynsymName)
	nDynamic := shName(".dynamic")
	nShstrtab := shName(".shstrtab")

	// Lay out the file. Sections start at 64 unless a program header table and
	// interpreter path precede them.
	off := ehSize
	phoff, interpOff := 0, 0
	if spec.interp != "" {
		phoff = off
		off = align8(off + phEntSize)
		interpOff = off
		off = align8(off + len(spec.interp) + 1) // + trailing NUL
	}
	textOff := off
	off = align8(off + len(spec.text))
	initOff := off
	off = align8(off + len(spec.text2))
	dynstrOff := off
	off = align8(off + len(dynstr))
	dynsymOff := off
	off = align8(off + len(dynsym))
	dynamicOff := off
	off = align8(off + len(dynamic))
	shstrtabOff := off
	off = align8(off + len(shstrtab))
	shoff := off

	// A file with no section header table is one where e_shoff and e_shnum are
	// both zero; debug/elf accepts that pair and reports no sections.
	if spec.noSections {
		shoff = 0
	}
	bufLen := off
	if shoff != 0 {
		bufLen = shoff + shEntSize*shNum
	}
	buf := make([]byte, bufLen)

	// ELF header.
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	buf[7] = byte(elf.ELFOSABI_NONE)
	le.PutUint16(buf[16:18], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:20], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:24], uint32(elf.EV_CURRENT))
	le.PutUint64(buf[32:40], uint64(phoff)) // e_phoff
	le.PutUint64(buf[40:48], uint64(shoff)) // e_shoff
	le.PutUint16(buf[52:54], ehSize)
	le.PutUint16(buf[54:56], phEntSize)
	phnum := 0
	if spec.interp != "" {
		phnum = 1
	}
	le.PutUint16(buf[56:58], uint16(phnum)) // e_phnum
	le.PutUint16(buf[58:60], shEntSize)
	if shoff != 0 {
		le.PutUint16(buf[60:62], shNum)    // e_shnum
		le.PutUint16(buf[62:64], secShstr) // e_shstrndx: .shstrtab is section 6
	}

	// Program header table, when requested. Only PT_INTERP is needed; a PT_PHDR
	// entry and a .interp section are conventional, not required - collectELF
	// only walks f.Progs for PT_INTERP and opens its file range.
	if spec.interp != "" {
		b := buf[phoff:]
		le.PutUint32(b[0:4], uint32(elf.PT_INTERP))
		le.PutUint32(b[4:8], uint32(elf.PF_R))             // p_flags: read (conventional)
		le.PutUint64(b[8:16], uint64(interpOff))           // p_offset
		le.PutUint64(b[16:24], 0)                          // p_vaddr
		le.PutUint64(b[24:32], 0)                          // p_paddr
		le.PutUint64(b[32:40], uint64(len(spec.interp)+1)) // p_filesz
		le.PutUint64(b[40:48], uint64(len(spec.interp)+1)) // p_memsz
		le.PutUint64(b[48:56], 1)                          // p_align
		copy(buf[interpOff:], spec.interp)                 // trailing NUL from make
	}

	// Section headers, written field by field in Section64's order.
	sh := func(i int, name uint32, typ elf.SectionType, flags uint64, offset, size uint64, link, info uint32, addralign, entsize uint64) {
		b := buf[shoff+i*shEntSize:]
		le.PutUint32(b[0:4], name)
		le.PutUint32(b[4:8], uint32(typ))
		le.PutUint64(b[8:16], flags)
		le.PutUint64(b[16:24], 0) // sh_addr
		le.PutUint64(b[24:32], offset)
		le.PutUint64(b[32:40], size)
		le.PutUint32(b[40:44], link)
		le.PutUint32(b[44:48], info)
		le.PutUint64(b[48:56], addralign)
		le.PutUint64(b[56:64], entsize)
	}

	if shoff != 0 {
		textFlags := uint64(elf.SHF_ALLOC)
		if spec.textExec {
			textFlags |= uint64(elf.SHF_EXECINSTR)
		}
		// sh_size is the declared size. spec.overrun adds bytes that were never
		// written, so the section claims more than the file holds - which the
		// extractor must notice by comparing what it read against this number
		// rather than by trusting it.
		sh(secText, nText, elf.SHT_PROGBITS, textFlags, uint64(textOff), uint64(len(spec.text))+spec.overrun, 0, 0, 8, 0)
		if spec.text2 != nil {
			initFlags := uint64(elf.SHF_ALLOC)
			if spec.text2Exec {
				initFlags |= uint64(elf.SHF_EXECINSTR)
			}
			sh(secInit, nInit, elf.SHT_PROGBITS, initFlags, uint64(initOff), uint64(len(spec.text2)), 0, 0, 8, 0)
		}
		sh(secDynstr, nDynstr, elf.SHT_STRTAB, uint64(elf.SHF_ALLOC), uint64(dynstrOff), uint64(len(dynstr)), 0, 0, 1, 0)
		if !spec.stripped {
			// sh_size is the declared size. zeroDynsym writes 0 over it, keeping
			// the section present but claiming no bytes - the shape that panics
			// debug/elf's 64-bit symbol reader.
			dynsymSize := uint64(len(dynsym))
			if spec.zeroDynsym {
				dynsymSize = 0
			}
			sh(secDynsym, nDynsym, elf.SHT_DYNSYM, uint64(elf.SHF_ALLOC), uint64(dynsymOff), dynsymSize, secDynstr, 1, 8, symEntSize)
		}
		sh(secDynamic, nDynamic, elf.SHT_DYNAMIC, uint64(elf.SHF_ALLOC), uint64(dynamicOff), uint64(len(dynamic)), secDynstr, 0, 8, dynEntSize)
		sh(secShstr, nShstrtab, elf.SHT_STRTAB, 0, uint64(shstrtabOff), uint64(len(shstrtab)), 0, 0, 1, 0)
	}

	copy(buf[textOff:], spec.text)
	copy(buf[initOff:], spec.text2)
	copy(buf[dynstrOff:], dynstr)
	copy(buf[dynsymOff:], dynsym)
	copy(buf[dynamicOff:], dynamic)
	copy(buf[shstrtabOff:], shstrtab)
	return buf
}

// uniformBytes returns n bytes whose histogram is exactly uniform over all 256
// values. The multiplier is coprime with 256, so the sequence is a permutation
// cycle and the entropy is exactly 8 bits per byte - which is what lets a test
// assert a number rather than a range.
func uniformBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

// elfCompressedFixture builds a minimal ELF64 with one section, .text, carrying
// SHF_EXECINSTR | SHF_COMPRESSED. Its compression header (an Elf64_Chdr) declares
// chSize as the uncompressed size, and its body is a real zlib stream of payload,
// so opening the section succeeds and yields len(payload) bytes.
//
// It exists because chSize is attacker-controlled and debug/elf does not range-
// check it: for a compressed section it copies ch_size straight into
// Section.Size, applying an int64 range check only to sh_size. A value at or
// above 2^63 therefore makes int64(Section.Size) negative, while the readable
// size stays small - the exact pair a short-read check has to compare, and the
// pair a signed comparison mis-handles.
func elfCompressedFixture(t *testing.T, chSize uint64, payload []byte) []byte {
	t.Helper()

	const (
		ehSize    = 64
		shEntSize = 64
		chdrSize  = 24 // Elf64_Chdr: uint32 + uint32 + uint64 + uint64
	)
	le := binary.LittleEndian
	align8 := func(n int) int { return (n + 7) &^ 7 }

	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	// The section body is the compression header followed by the compressed
	// stream. debug/elf reads the header at load time and decompresses from
	// compressionOffset (the header's own size) onward.
	body := make([]byte, chdrSize+z.Len())
	le.PutUint32(body[0:4], uint32(elf.COMPRESS_ZLIB)) // ch_type
	le.PutUint32(body[4:8], 0)                         // ch_reserved
	le.PutUint64(body[8:16], chSize)                   // ch_size (uncompressed)
	le.PutUint64(body[16:24], 1)                       // ch_addralign
	copy(body[chdrSize:], z.Bytes())

	shstrtab := []byte{0}
	nameText := uint32(len(shstrtab))
	shstrtab = append(shstrtab, ".text"...)
	shstrtab = append(shstrtab, 0)
	nameShstr := uint32(len(shstrtab))
	shstrtab = append(shstrtab, ".shstrtab"...)
	shstrtab = append(shstrtab, 0)

	bodyOff := ehSize
	shstrOff := align8(bodyOff + len(body))
	shoff := align8(shstrOff + len(shstrtab))
	buf := make([]byte, shoff+shEntSize*3)

	// ELF header: class 64, little-endian, ET_DYN, no program headers.
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	buf[7] = byte(elf.ELFOSABI_NONE)
	le.PutUint16(buf[16:18], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:20], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:24], uint32(elf.EV_CURRENT))
	le.PutUint64(buf[40:48], uint64(shoff)) // e_shoff
	le.PutUint16(buf[52:54], ehSize)
	le.PutUint16(buf[58:60], shEntSize)
	le.PutUint16(buf[60:62], 3) // e_shnum: null, .text, .shstrtab
	le.PutUint16(buf[62:64], 2) // e_shstrndx

	copy(buf[bodyOff:], body)
	copy(buf[shstrOff:], shstrtab)

	sh := func(i int, name uint32, typ elf.SectionType, flags uint64, offset, size, addralign uint64) {
		b := buf[shoff+i*shEntSize:]
		le.PutUint32(b[0:4], name)
		le.PutUint32(b[4:8], uint32(typ))
		le.PutUint64(b[8:16], flags)
		le.PutUint64(b[24:32], offset)
		le.PutUint64(b[32:40], size)
		le.PutUint64(b[48:56], addralign)
	}
	// .text is executable and compressed; debug/elf takes the section's size from
	// the compression header, so ch_size is what a reader reports as its size.
	// Only the two flags it needs are set - a compressed section that is also
	// SHF_ALLOC is rejected by the reader.
	sh(1, nameText, elf.SHT_PROGBITS, uint64(elf.SHF_EXECINSTR)|uint64(elf.SHF_COMPRESSED), uint64(bodyOff), uint64(len(body)), 1)
	sh(2, nameShstr, elf.SHT_STRTAB, 0, uint64(shstrOff), uint64(len(shstrtab)), 1)
	return buf
}
