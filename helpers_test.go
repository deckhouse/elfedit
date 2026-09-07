package elfedit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
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
