package elfedit

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

type encoding struct {
	name  string
	class elf.Class
	order binary.ByteOrder
}

var encodings = []encoding{
	{"32le", elf.ELFCLASS32, binary.LittleEndian},
	{"32be", elf.ELFCLASS32, binary.BigEndian},
	{"64le", elf.ELFCLASS64, binary.LittleEndian},
	{"64be", elf.ELFCLASS64, binary.BigEndian},
}

// Fixtures use standard-library ABI structures independently of the writer.
func fixture(t testing.TB, enc encoding, machine elf.Machine, count int, namesLast bool) []byte {
	t.Helper()
	var out bytes.Buffer
	headerSize, sectionSize, programSize := 64, 64, 56
	if enc.class == elf.ELFCLASS32 {
		headerSize, sectionSize, programSize = 52, 40, 32
	}
	names := []byte("\x00.shstrtab\x00.text\x00.bss\x00.extra\x00")
	namesIndex := 1
	if namesLast {
		namesIndex = count - 1
	}
	namesOffset, textOffset := 256, 512
	shoff := 1024
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(enc.class), 1, 1, 0, 0, 9, 8, 7, 6, 5, 4, 3}
	if enc.order == binary.BigEndian {
		ident[5] = 2
	}
	hCount, hNames := uint16(count), uint16(namesIndex)
	if count >= int(elf.SHN_LORESERVE) {
		hCount = 0
	}
	if namesIndex >= int(elf.SHN_LORESERVE) {
		hNames = uint16(elf.SHN_XINDEX)
	}
	write := func(v any) {
		t.Helper()
		if err := binary.Write(&out, enc.order, v); err != nil {
			t.Fatal(err)
		}
	}
	if enc.class == elf.ELFCLASS32 {
		write(elf.Header32{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: 1, Entry: 0x10000 + uint32(textOffset), Phoff: uint32(headerSize), Shoff: uint32(shoff), Flags: 0x1234, Ehsize: uint16(headerSize), Phentsize: uint16(programSize), Phnum: 1, Shentsize: uint16(sectionSize), Shnum: hCount, Shstrndx: hNames})
		write(elf.Prog32{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: uint32(textOffset), Vaddr: 0x10000 + uint32(textOffset), Filesz: 4, Memsz: 16, Align: 1})
	} else {
		write(elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: 1, Entry: 0x10000 + uint64(textOffset), Phoff: uint64(headerSize), Shoff: uint64(shoff), Flags: 0x1234, Ehsize: uint16(headerSize), Phentsize: uint16(programSize), Phnum: 1, Shentsize: uint16(sectionSize), Shnum: hCount, Shstrndx: hNames})
		write(elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: uint64(textOffset), Vaddr: 0x10000 + uint64(textOffset), Filesz: 4, Memsz: 16, Align: 1})
	}
	body := bytes.Repeat([]byte{0xa5}, shoff-out.Len())
	copy(body[namesOffset-out.Len():], names)
	copy(body[textOffset-out.Len():], []byte{1, 2, 3, 4})
	if _, err := out.Write(body); err != nil {
		t.Fatal(err)
	}
	for i := range count {
		s := elf.Section64{Type: uint32(elf.SHT_PROGBITS), Off: 640, Size: 0, Addralign: 1}
		switch i {
		case 0:
			s = elf.Section64{}
			if hCount == 0 {
				s.Size = uint64(count)
			}
			if hNames == uint16(elf.SHN_XINDEX) {
				s.Link = uint32(namesIndex)
			}
		case namesIndex:
			s = elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(namesOffset), Size: uint64(len(names)), Addralign: 16}
		case 2:
			s = elf.Section64{Name: 11, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: 0x10000 + uint64(textOffset), Off: uint64(textOffset), Size: 4, Addralign: 4}
		case 3:
			s = elf.Section64{Name: 17, Type: uint32(elf.SHT_NOBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE), Addr: 0x20000, Off: 1 << 28, Size: 4096, Addralign: 16}
		}
		if enc.class == elf.ELFCLASS32 {
			write(elf.Section32{Name: s.Name, Type: s.Type, Flags: uint32(s.Flags), Addr: uint32(s.Addr), Off: uint32(s.Off), Size: uint32(s.Size), Link: s.Link, Info: s.Info, Addralign: uint32(s.Addralign), Entsize: uint32(s.Entsize)})
		} else {
			write(s)
		}
	}
	if _, err := out.WriteString("opaque overlay survives\x00"); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func openELF(t testing.TB, data []byte) *elf.File {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func assertPreserved(t testing.TB, input, output []byte) {
	t.Helper()
	if len(output) < len(input) {
		t.Fatal("output truncated original file")
	}
	for i, b := range input {
		if elf.Class(input[elf.EI_CLASS]) == elf.ELFCLASS32 {
			if i >= 32 && i < 36 || i >= 46 && i < 52 {
				continue
			}
		} else if i >= 40 && i < 48 || i >= 58 && i < 64 {
			continue
		}
		if output[i] != b {
			t.Fatalf("original byte %d changed: %#x -> %#x", i, b, output[i])
		}
	}
}

func assertSectionEditPreserved(t testing.TB, input, output []byte, name string) {
	t.Helper()
	if len(output) != len(input) {
		assertPreserved(t, input, output)
		return
	}
	f, err := readFile(context.Background(), bytes.NewReader(input), int64(len(input)))
	if err != nil {
		t.Fatal(err)
	}
	// An in-place edit leaves the table where it is, so unlike after an append
	// the header fields naming it keep their bytes.
	if !bytes.Equal(output[:len(f.header)], input[:len(f.header)]) {
		t.Fatal("same-sized edit changed the ELF header")
	}
	for i, s := range f.sections {
		if s.Type == uint32(elf.SHT_NULL) {
			continue
		}
		end := bytes.IndexByte(f.names[s.Name:], 0)
		if string(f.names[int(s.Name):int(s.Name)+end]) != name {
			continue
		}
		restored := bytes.Clone(output)
		copy(restored[s.Off:s.Off+s.Size], input[s.Off:s.Off+s.Size])
		entry := f.shoff + uint64(i*f.shentsize)
		copy(restored[entry:entry+uint64(f.shentsize)], input[entry:entry+uint64(f.shentsize)])
		assertPreserved(t, input, restored)
		return
	}
	t.Fatalf("same-sized edit did not find section %q in input", name)
}

func putFixtureSegment(t testing.TB, enc encoding, input []byte, offset, size uint64) {
	t.Helper()
	var out bytes.Buffer
	var value any = elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R), Off: offset, Vaddr: 0x30000, Filesz: size, Memsz: size, Align: 1}
	headerSize := 64
	if enc.class == elf.ELFCLASS32 {
		value = elf.Prog32{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R), Off: uint32(offset), Vaddr: 0x30000, Filesz: uint32(size), Memsz: uint32(size), Align: 1}
		headerSize = 52
	}
	if err := binary.Write(&out, enc.order, value); err != nil {
		t.Fatal(err)
	}
	copy(input[headerSize:], out.Bytes())
}

func putFixtureSection(t testing.TB, enc encoding, input []byte, index int, s elf.Section64) {
	t.Helper()
	var out bytes.Buffer
	var value any = s
	if enc.class == elf.ELFCLASS32 {
		value = elf.Section32{Name: s.Name, Type: s.Type, Flags: uint32(s.Flags), Addr: uint32(s.Addr), Off: uint32(s.Off), Size: uint32(s.Size), Link: s.Link, Info: s.Info, Addralign: uint32(s.Addralign), Entsize: uint32(s.Entsize)}
	}
	if err := binary.Write(&out, enc.order, value); err != nil {
		t.Fatal(err)
	}
	copy(input[1024+index*out.Len():], out.Bytes())
}

func sectionTable(t testing.TB, enc encoding, input []byte) (int, int) {
	t.Helper()
	if enc.class == elf.ELFCLASS32 {
		return int(enc.order.Uint32(input[32:36])), int(enc.order.Uint16(input[46:48]))
	}
	return int(enc.order.Uint64(input[40:48])), int(enc.order.Uint16(input[58:60]))
}

type streamVerifier struct {
	source sparseReader
	bytes  int64
	tail   bytes.Buffer
}

var _ io.Writer = (*streamVerifier)(nil)

func (w *streamVerifier) Write(p []byte) (int, error) {
	start, end := max(w.bytes, 64), min(w.bytes+int64(len(p)), w.source.size)
	if start < end {
		want := make([]byte, end-start)
		if _, err := w.source.ReadAt(want, start); err != nil {
			return 0, err
		}
		if !bytes.Equal(p[start-w.bytes:end-w.bytes], want) {
			return 0, fmt.Errorf("streamed source differs at offset %d", start)
		}
	}
	if w.bytes+int64(len(p)) > w.source.size {
		if _, err := w.tail.Write(p[max(w.source.size-w.bytes, 0):]); err != nil {
			return 0, err
		}
	}
	w.bytes += int64(len(p))
	return len(p), nil
}

type interruptWriter struct {
	bytes     int
	after     int
	interrupt func()
	err       error
}

var _ io.Writer = (*interruptWriter)(nil)

func (w *interruptWriter) Write(p []byte) (int, error) {
	w.bytes += len(p)
	if w.bytes >= w.after {
		w.interrupt()
		if w.err != nil {
			return 0, w.err
		}
	}
	return len(p), nil
}

func sharedNamesFixture(t testing.TB, enc encoding, count int) []byte {
	t.Helper()
	input := fixture(t, enc, elf.EM_X86_64, count, false)
	names := []byte("\x00.shstrtab\x00.text\x00.bss\x00.extra\x00.strtab\x00.symtab\x00symbol\x00")
	copy(input[256:], names)
	putFixtureSection(t, enc, input, 1, elf.Section64{Name: 29, Type: uint32(elf.SHT_STRTAB), Off: 256, Size: uint64(len(names)), Addralign: 1})
	var symbols bytes.Buffer
	var zero, symbol any = elf.Sym64{}, elf.Sym64{Name: 45, Info: 0x12, Shndx: 2, Value: 0x10200, Size: 4}
	if enc.class == elf.ELFCLASS32 {
		zero, symbol = elf.Sym32{}, elf.Sym32{Name: 45, Info: 0x12, Shndx: 2, Value: 0x10200, Size: 4}
	}
	for _, s := range []any{zero, symbol} {
		if err := binary.Write(&symbols, enc.order, s); err != nil {
			t.Fatal(err)
		}
	}
	copy(input[768:], symbols.Bytes())
	putFixtureSection(t, enc, input, 4, elf.Section64{Name: 37, Type: uint32(elf.SHT_SYMTAB), Off: 768, Size: uint64(symbols.Len()), Link: 1, Info: 1, Addralign: 8, Entsize: uint64(binary.Size(symbol))})
	return input
}

func assertOriginalSections(t testing.TB, enc encoding, input, output []byte) {
	t.Helper()
	before, after := openELF(t, input), openELF(t, output)
	oldTable, entrySize := sectionTable(t, enc, input)
	newTable, _ := sectionTable(t, enc, output)
	for i := 1; i < len(before.Sections); i++ {
		if !bytes.Equal(input[oldTable+i*entrySize:oldTable+(i+1)*entrySize], output[newTable+i*entrySize:newTable+(i+1)*entrySize]) {
			t.Fatalf("original section %d header changed", i)
		}
		if before.Sections[i].Name != after.Sections[i].Name {
			t.Fatalf("original section %d name changed", i)
		}
	}
	assertPreserved(t, input, output)
}

type nonemptyReader struct{ *bytes.Reader }

func (r nonemptyReader) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, fmt.Errorf("unexpected zero-length ReadAt")
	}
	return r.Reader.ReadAt(p, off)
}

type cancelOnRead struct {
	*bytes.Reader
	offset int64
	cancel context.CancelFunc
}

func (r cancelOnRead) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.Reader.ReadAt(p, off)
	if off == r.offset {
		r.cancel()
	}
	return n, err
}

func assertActiveMetadataPreserved(t testing.TB, input, output []byte, name string, preserve bool) {
	t.Helper()
	before, err := readFile(context.Background(), bytes.NewReader(input), int64(len(input)))
	if err != nil {
		t.Fatal(err)
	}
	after, err := readFile(context.Background(), bytes.NewReader(output), int64(len(output)))
	if err != nil {
		t.Fatal(err)
	}
	target := -1
	for i, s := range before.sections {
		if s.Type == uint32(elf.SHT_NULL) {
			continue
		}
		start := uint64(s.Name)
		end := start + uint64(len(name))
		if end < uint64(len(before.names)) && before.names[end] == 0 && bytes.Equal(before.names[start:end], []byte(name)) {
			target = i
		}
	}
	detach := target < 0 && preserve && before.shoff != 0
	count := len(before.sections)
	if target < 0 {
		count++
		if detach {
			count++
		}
	}
	if len(after.sections) != count {
		t.Fatalf("section count=%d want=%d", len(after.sections), count)
	}
	if !detach && after.shstrndx != before.shstrndx {
		t.Fatal("selected name-table index changed")
	}
	for i, want := range before.sections {
		got := after.sections[i]
		if i == 0 {
			got.Size, want.Size, got.Link, want.Link = 0, 0, 0, 0
		}
		if i == target {
			got.Type, want.Type = 0, 0
			got.Flags, want.Flags = 0, 0
			got.Addralign, want.Addralign = 0, 0
			got.Off, want.Off, got.Size, want.Size = 0, 0, 0, 0
		}
		if target < 0 && i == before.shstrndx && !detach {
			got.Off, want.Off, got.Size, want.Size = 0, 0, 0, 0
		}
		if got != want {
			t.Fatalf("active section %d metadata changed: got=%+v want=%+v", i, got, want)
		}
	}
	if !bytes.HasPrefix(after.names, before.names) {
		t.Fatal("original numeric name offsets changed")
	}
}
