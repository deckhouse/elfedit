package elfedit

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
)

func metadataFixture(t *testing.T, enc encoding) []byte {
	t.Helper()
	names := []byte("\x00.shstrtab\x00.strtab\x00.symtab\x00.merge\x00.group\x00.note.test\x00")
	name := func(s string) uint32 { return uint32(bytes.Index(names, []byte(s+"\x00"))) }
	word, symbolSize, sectionSize := 8, 24, 64
	if enc.class == elf.ELFCLASS32 {
		word, symbolSize, sectionSize = 4, 16, 40
	}
	sections := []elf.Section64{
		{},
		{Name: name(".shstrtab"), Type: uint32(elf.SHT_STRTAB), Off: 64, Size: uint64(len(names)), Addralign: 1},
		{Name: name(".strtab"), Type: uint32(elf.SHT_STRTAB), Off: 176, Size: 14, Addralign: 1},
		{Name: name(".symtab"), Type: uint32(elf.SHT_SYMTAB), Off: 192, Size: uint64(2 * symbolSize), Link: 2, Info: 1, Addralign: uint64(word), Entsize: uint64(symbolSize)},
		{Name: name(".merge"), Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_MERGE | elf.SHF_STRINGS), Off: 256, Size: 4, Addralign: 1, Entsize: 1},
		{Name: name(".group"), Type: uint32(elf.SHT_GROUP), Off: 272, Size: 8, Link: 3, Info: 1, Addralign: 4, Entsize: 4},
		{Name: name(".note.test"), Type: uint32(elf.SHT_NOTE), Flags: uint64(elf.SHF_GROUP), Off: 288, Size: 24, Addralign: 4},
	}
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(enc.class), byte(elf.ELFDATA2LSB), 1}
	if enc.order == binary.BigEndian {
		ident[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	}
	var header, symbols bytes.Buffer
	write := func(dst *bytes.Buffer, v any) {
		t.Helper()
		if err := binary.Write(dst, enc.order, v); err != nil {
			t.Fatal(err)
		}
	}
	if enc.class == elf.ELFCLASS32 {
		write(&header, elf.Header32{Ident: ident, Type: uint16(elf.ET_REL), Machine: uint16(elf.EM_ARM), Version: 1, Shoff: 1024, Ehsize: 52, Shentsize: 40, Shnum: uint16(len(sections)), Shstrndx: 1})
		write(&symbols, elf.Sym32{})
		write(&symbols, elf.Sym32{Name: 1, Info: byte(elf.STB_GLOBAL) << 4, Shndx: uint16(elf.SHN_ABS), Value: 1})
	} else {
		write(&header, elf.Header64{Ident: ident, Type: uint16(elf.ET_REL), Machine: uint16(elf.EM_AARCH64), Version: 1, Shoff: 1024, Ehsize: 64, Shentsize: 64, Shnum: uint16(len(sections)), Shstrndx: 1})
		write(&symbols, elf.Sym64{})
		write(&symbols, elf.Sym64{Name: 1, Info: byte(elf.STB_GLOBAL) << 4, Shndx: uint16(elf.SHN_ABS), Value: 1})
	}
	input := make([]byte, 1024+len(sections)*sectionSize)
	copy(input, header.Bytes())
	copy(input[64:], names)
	copy(input[176:], "\x00symbol\x00other\x00")
	copy(input[192:], symbols.Bytes())
	copy(input[256:], "old\x00")
	enc.order.PutUint32(input[272:], 1)
	enc.order.PutUint32(input[276:], 6)
	copy(input[288:], notePayload(enc.order))
	for i, s := range sections {
		putFixtureSection(t, enc, input, i, s)
	}
	f := openELF(t, input)
	syms, err := f.Symbols()
	if err != nil || len(syms) != 1 || syms[0].Name != "symbol" {
		t.Fatalf("invalid symbol fixture: %v %v", syms, err)
	}
	if f.Type != elf.ET_REL || f.Sections[6].Flags != elf.SHF_GROUP || f.Sections[5].Link != 3 || f.Sections[5].Info != 1 {
		t.Fatal("invalid group fixture")
	}
	return input
}

func TestCreationRequiresDependentMetadata(t *testing.T) {
	types := []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_REL, elf.SHT_RELA, elf.SHT_HASH, elf.SHT_DYNAMIC, elf.SHT_GROUP, elf.SHT_SYMTAB_SHNDX, elf.SectionType(19)}
	for _, enc := range encodings {
		input := metadataFixture(t, enc)
		cases := []SectionOptions{{Flags: elf.SHF_MERGE}, {Flags: elf.SHF_STRINGS}, {Flags: elf.SHF_MERGE | elf.SHF_STRINGS}}
		for _, typ := range types {
			cases = append(cases, SectionOptions{Type: typ})
		}
		for _, opts := range cases {
			t.Run(fmt.Sprintf("%s/type%d/flags%d", enc.name, opts.Type, opts.Flags), func(t *testing.T) {
				// A null symbol and a terminated string are valid opaque payloads; headers are the missing input.
				payload := make([]byte, 24)
				if enc.class == elf.ELFCLASS32 {
					payload = payload[:16]
				}
				pristine := bytes.Clone(input)
				out, err := SetSection(context.Background(), input, ".new", payload, opts)

				fields := map[elf.SectionType]string{elf.SHT_SYMTAB: "Entsize, Link and Info", elf.SHT_DYNSYM: "Entsize, Link and Info", elf.SHT_REL: "Entsize and Link", elf.SHT_RELA: "Entsize and Link", elf.SHT_HASH: "Link", elf.SHT_DYNAMIC: "Entsize and Link", elf.SHT_GROUP: "Entsize, Link and Info", elf.SHT_SYMTAB_SHNDX: "Entsize and Link", elf.SectionType(19): "Entsize"}
				kind := opts.Type.String()
				if opts.Type == elf.SectionType(19) {
					kind = "SHT_RELR"
				}
				want := fmt.Sprintf("edit ELF: cannot create %s: required metadata (%s) is unavailable in SectionOptions", kind, fields[opts.Type])
				if opts.Flags != 0 {
					want = fmt.Sprintf("edit ELF: cannot create section with %s: Entsize is unavailable in SectionOptions", opts.Flags)
				}
				if err == nil || err.Error() != want || out != nil {
					t.Fatalf("creation returned output=%d err=%v; want dependent-metadata rejection", len(out), err)
				}
				var streamed bytes.Buffer
				streamErr := WriteSection(context.Background(), &streamed, bytes.NewReader(input), int64(len(input)), ".new", payload, opts)
				if streamErr == nil || streamErr.Error() != err.Error() || streamed.Len() != 0 {
					t.Fatalf("streamed creation output=%d err=%v", streamed.Len(), streamErr)
				}
				if !bytes.Equal(input, pristine) {
					t.Fatal("input changed")
				}
			})
		}
	}
}

func TestCreationAllowsOpaqueMetadata(t *testing.T) {
	for _, enc := range encodings {
		input := metadataFixture(t, enc)
		for _, typ := range []elf.SectionType{elf.SHT_PROGBITS, elf.SHT_NOTE, elf.SHT_STRTAB, elf.SHT_LOOS + 123, elf.SHT_LOPROC + 123, elf.SectionType(0x80000000)} {
			t.Run(fmt.Sprintf("%s/type%x", enc.name, uint32(typ)), func(t *testing.T) {
				data := notePayload(enc.order)
				if typ == elf.SHT_STRTAB {
					data = []byte("\x00normal\x00")
				}
				opts := SectionOptions{Type: typ, Alignment: 4}
				out, err := SetSection(context.Background(), input, ".new", data, opts)
				if err != nil {
					t.Fatal(err)
				}
				var stream bytes.Buffer
				if err := WriteSection(context.Background(), &stream, bytes.NewReader(input), int64(len(input)), ".new", data, opts); err != nil || !bytes.Equal(stream.Bytes(), out) {
					t.Fatalf("API difference: %v", err)
				}
				s := openELF(t, out).Section(".new")
				got, err := s.Data()
				if err != nil || s.Type != typ || !bytes.Equal(got, data) {
					t.Fatalf("new metadata: %+v, %v", s.SectionHeader, err)
				}
			})
		}
	}
}

func TestDependentMetadataReplacement(t *testing.T) {
	for _, enc := range encodings {
		for _, name := range []string{".merge", ".symtab"} {
			for _, appendData := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/append%v", enc.name, name, appendData), func(t *testing.T) {
					input := metadataFixture(t, enc)
					before := openELF(t, input).Section(name)
					data, err := before.Data()
					if err != nil {
						t.Fatal(err)
					}
					data = bytes.Clone(data)
					if name == ".merge" {
						copy(data, "new\x00")
						if appendData {
							data = append(data, []byte("more\x00")...)
						}
					} else if appendData {
						var symbol bytes.Buffer
						if enc.class == elf.ELFCLASS32 {
							err = binary.Write(&symbol, enc.order, elf.Sym32{Name: 8, Info: byte(elf.STB_GLOBAL) << 4, Shndx: uint16(elf.SHN_ABS), Value: 2})
						} else {
							err = binary.Write(&symbol, enc.order, elf.Sym64{Name: 8, Info: byte(elf.STB_GLOBAL) << 4, Shndx: uint16(elf.SHN_ABS), Value: 2})
						}
						if err != nil {
							t.Fatal(err)
						}
						data = append(data, symbol.Bytes()...)
					}
					opts := SectionOptions{Type: before.Type, Flags: before.Flags, Alignment: before.Addralign}
					out, err := SetSection(context.Background(), input, name, data, opts)
					if err != nil {
						t.Fatal(err)
					}
					var stream bytes.Buffer
					if err := WriteSection(context.Background(), &stream, bytes.NewReader(input), int64(len(input)), name, data, opts); err != nil || !bytes.Equal(stream.Bytes(), out) {
						t.Fatalf("API difference: %v", err)
					}
					f := openELF(t, out)
					after := f.Section(name)
					if after.Link != before.Link || after.Info != before.Info || after.Entsize != before.Entsize {
						t.Fatal("dependent metadata changed")
					}
					if appendData != (after.Offset >= uint64(len(input))) {
						t.Fatal("wrong replacement path")
					}
					got, err := after.Data()
					if err != nil || !bytes.Equal(got, data) {
						t.Fatalf("payload: %v", err)
					}
					if name == ".symtab" {
						symbols, err := f.Symbols()
						want := 1
						if appendData {
							want = 2
						}
						if err != nil || len(symbols) != want {
							t.Fatalf("symbols: %v %v", symbols, err)
						}
					}
				})
			}
		}
	}
}

func TestExplicitGroupFlagsAndStagedMember(t *testing.T) {
	for _, enc := range encodings {
		input := metadataFixture(t, enc)
		for _, flags := range []elf.SectionFlag{0, elf.SHF_GROUP, elf.SHF_WRITE} {
			for _, alignment := range []uint64{4, 1024} {
				opts := SectionOptions{Type: elf.SHT_NOTE, Flags: flags, Alignment: alignment}
				out, err := SetSection(context.Background(), input, ".note.test", notePayload(enc.order), opts)
				if err != nil {
					t.Fatal(err)
				}
				if openELF(t, out).Section(".note.test").Flags != flags {
					t.Fatal("editor did not replace flags exactly")
				}
				var stream bytes.Buffer
				if err := WriteSection(context.Background(), &stream, bytes.NewReader(input), int64(len(input)), ".note.test", notePayload(enc.order), opts); err != nil || !bytes.Equal(stream.Bytes(), out) {
					t.Fatalf("API difference: %v", err)
				}
			}
		}
		staged, err := SetSection(context.Background(), input, ".member", []byte("member"), SectionOptions{Flags: elf.SHF_GROUP})
		if err != nil {
			t.Fatal(err)
		}
		members := make([]byte, 12)
		enc.order.PutUint32(members, 1)
		enc.order.PutUint32(members[4:], 6)
		enc.order.PutUint32(members[8:], 7)
		var final bytes.Buffer
		if err := WriteSection(context.Background(), &final, bytes.NewReader(staged), int64(len(staged)), ".group", members, SectionOptions{Type: elf.SHT_GROUP, Alignment: 4}); err != nil {
			t.Fatal(err)
		}
		f := openELF(t, final.Bytes())
		group := f.Section(".group")
		actual, err := group.Data()
		if err != nil || !bytes.Equal(actual, members) || group.Link != 3 || group.Info != 1 || group.Entsize != 4 {
			t.Fatal("staged group metadata changed")
		}
		for _, index := range []int{6, 7} {
			if f.Sections[index].Flags&elf.SHF_GROUP == 0 {
				t.Fatal("final member missing group flag")
			}
		}
	}
}

func TestSpecificationObject(t *testing.T) {
	input, err := os.ReadFile("testdata/spec/sections.elf")
	if err != nil {
		t.Fatal(err)
	}
	f := openELF(t, input)
	if f.Type != elf.ET_REL || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		t.Fatal("unexpected fixture identity")
	}
	symbols, err := f.Symbols()
	if err != nil || len(symbols) != 1 || symbols[0].Name != "spec_group" || symbols[0].Section != elf.SHN_ABS {
		t.Fatalf("symbols: %v %v", symbols, err)
	}
	group := f.Section(".group")
	members, err := group.Data()
	if err != nil || len(members) != 8 || f.ByteOrder.Uint32(members) != 1 || group.Entsize != 4 || group.Info != 1 || f.Sections[group.Link].Type != elf.SHT_SYMTAB {
		t.Fatal("invalid group fixture")
	}
	index := f.ByteOrder.Uint32(members[4:])
	if f.Sections[index].Name != ".note.test" || f.Sections[index].Flags != elf.SHF_GROUP {
		t.Fatal("group membership mismatch")
	}
	original := f.Section(".merge")
	if original.Entsize != 1 || original.Flags != elf.SHF_MERGE|elf.SHF_STRINGS {
		t.Fatal("invalid merge fixture")
	}
	for _, data := range [][]byte{[]byte("replaced\x00"), []byte("longer replacement\x00")} {
		opts := SectionOptions{Type: elf.SHT_PROGBITS, Flags: elf.SHF_MERGE | elf.SHF_STRINGS, Alignment: 1}
		out, err := SetSection(context.Background(), input, ".merge", data, opts)
		if err != nil {
			t.Fatal(err)
		}
		var streamed bytes.Buffer
		if err := WriteSection(context.Background(), &streamed, bytes.NewReader(input), int64(len(input)), ".merge", data, opts); err != nil || !bytes.Equal(out, streamed.Bytes()) {
			t.Fatalf("API difference: %v", err)
		}
		after := openELF(t, out)
		s := after.Section(".merge")
		if s.Link != original.Link || s.Info != original.Info || s.Entsize != 1 {
			t.Fatal("merge metadata changed")
		}
		got, err := s.Data()
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("merge payload: %v", err)
		}
		for i, want := range f.Sections {
			if want != original && after.Sections[i].SectionHeader != want.SectionHeader {
				t.Fatalf("unrelated active metadata %d changed", i)
			}
		}
	}
}

func TestUnsupportedNameTableFixtures(t *testing.T) {
	for _, enc := range encodings {
		for _, compressed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/compressed%v", enc.name, compressed), func(t *testing.T) {
				input := metadataFixture(t, enc)
				parsed, err := readFile(context.Background(), bytes.NewReader(input), int64(len(input)))
				if err != nil {
					t.Fatal(err)
				}
				want := "read ELF: missing or invalid section-name table"
				if compressed {
					var encoded bytes.Buffer
					var header any = elf.Chdr64{Type: uint32(elf.COMPRESS_ZLIB), Size: uint64(len(parsed.names)), Addralign: 1}
					alignment := uint64(8)
					if enc.class == elf.ELFCLASS32 {
						header = elf.Chdr32{Type: uint32(elf.COMPRESS_ZLIB), Size: uint32(len(parsed.names)), Addralign: 1}
						alignment = 4
					}
					if err := binary.Write(&encoded, enc.order, header); err != nil {
						t.Fatal(err)
					}
					z := zlib.NewWriter(&encoded)
					if _, err := z.Write(parsed.names); err != nil {
						t.Fatal(err)
					}
					if err := z.Close(); err != nil {
						t.Fatal(err)
					}
					str := parsed.sections[1]
					str.Flags = uint64(elf.SHF_COMPRESSED)
					str.Off = uint64(len(input))
					str.Size = uint64(encoded.Len())
					str.Addralign = alignment
					input = append(input, encoded.Bytes()...)
					putFixtureSection(t, enc, input, 1, str)
					want = "read ELF: compressed section-name table is unsupported"
				} else {
					for i, s := range parsed.sections {
						s.Name = 0
						putFixtureSection(t, enc, input, i, s)
					}
					if enc.class == elf.ELFCLASS32 {
						enc.order.PutUint16(input[50:52], 0)
					} else {
						enc.order.PutUint16(input[62:64], 0)
					}
				}
				pristine := bytes.Clone(input)
				out, err := SetSection(context.Background(), input, ".new", []byte("data"), SectionOptions{})
				if err == nil || err.Error() != want || out != nil {
					t.Fatalf("output=%d err=%v want=%q", len(out), err, want)
				}
				var streamed bytes.Buffer
				err = WriteSection(context.Background(), &streamed, bytes.NewReader(input), int64(len(input)), ".new", []byte("data"), SectionOptions{})
				if err == nil || err.Error() != want || streamed.Len() != 0 || !bytes.Equal(pristine, input) {
					t.Fatalf("streamed rejection: %v", err)
				}
			})
		}
	}
}
