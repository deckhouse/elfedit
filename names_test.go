package elfedit

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestPreserveSectionNameTable(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			for _, layout := range []string{"shared", "nonshared", "canonical", "allocated", "mapped", "collision"} {
				t.Run(layout, func(t *testing.T) {
					input := sharedNamesFixture(t, enc, 6)
					old := openELF(t, input).Sections[1]
					s := elf.Section64{Name: 29, Type: uint32(elf.SHT_STRTAB), Off: old.Offset, Size: old.Size, Addralign: 1}
					switch layout {
					case "nonshared":
						putFixtureSection(t, enc, input, 4, elf.Section64{Type: uint32(elf.SHT_PROGBITS), Off: 768})
					case "canonical":
						s.Name = 1
					case "allocated":
						s.Flags = uint64(elf.SHF_ALLOC)
					case "mapped":
						putFixtureSegment(t, enc, input, old.Offset, old.Size)
					case "collision":
						putFixtureSection(t, enc, input, 5, elf.Section64{Name: 1, Type: uint32(elf.SHT_PROGBITS), Off: 900, Size: 4, Addralign: 1})
						copy(input[900:], "user")
					}
					putFixtureSection(t, enc, input, 1, s)
					pristine := bytes.Clone(input)
					opts := SectionOptions{PreserveSectionNameTable: true}
					output, err := SetSection(context.Background(), input, ".new", []byte("payload"), opts)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(input, pristine) {
						t.Fatal("input mutated")
					}
					assertOriginalSections(t, enc, input, output)
					before, after := openELF(t, input), openELF(t, output)
					if len(after.Sections) != len(before.Sections)+2 {
						t.Fatal("expected target and detached name table")
					}
					f, err := readFile(context.Background(), bytes.NewReader(output), int64(len(output)))
					if err != nil {
						t.Fatal(err)
					}
					names := after.Sections[f.shstrndx]
					if f.shstrndx < len(before.Sections) || names.Name != ".shstrtab" || names.Type != elf.SHT_STRTAB || names.Flags != 0 || names.Addralign != 1 {
						t.Fatalf("invalid detached name table: %+v", names.SectionHeader)
					}
					if !bytes.HasPrefix(f.names, input[old.Offset:old.Offset+old.Size]) {
						t.Fatal("original names not retained as prefix")
					}
					if layout != "nonshared" {
						want, err := before.Symbols()
						if err != nil || len(want) != 1 || want[0].Name != "symbol" {
							t.Fatalf("invalid symbol fixture: %+v %v", want, err)
						}
						got, err := after.Symbols()
						if err != nil || !reflect.DeepEqual(got, want) {
							t.Fatalf("symbols changed: %+v %v", got, err)
						}
					}
					var streamed bytes.Buffer
					if err := WriteSection(context.Background(), &streamed, bytes.NewReader(input), int64(len(input)), ".new", []byte("payload"), opts); err != nil || !bytes.Equal(streamed.Bytes(), output) {
						t.Fatalf("streaming differs: %v", err)
					}
					for _, payload := range []string{"replace", "larger replacement"} {
						replaced, err := SetSection(context.Background(), output, ".new", []byte(payload), opts)
						if err != nil {
							t.Fatal(err)
						}
						if len(openELF(t, replaced).Sections) != len(after.Sections) {
							t.Fatal("replacement detached again")
						}
						assertSectionEditPreserved(t, output, replaced, ".new")
					}
					for _, limit := range []uint64{uint64(len(output)) - 1, uint64(len(output))} {
						var dst bytes.Buffer
						opts.MaxOutputSize = limit
						err := WriteSection(context.Background(), &dst, bytes.NewReader(input), int64(len(input)), ".new", []byte("payload"), opts)
						if limit < uint64(len(output)) {
							if err == nil || dst.Len() != 0 {
								t.Fatalf("short budget accepted: %v", err)
							}
						} else if err != nil || !bytes.Equal(dst.Bytes(), output) {
							t.Fatalf("exact budget failed: %v", err)
						}
					}
				})
			}
		})
	}
}

func TestPreserveNameTableOptIn(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			input := sharedNamesFixture(t, enc, 6)
			putFixtureSection(t, enc, input, 5, elf.Section64{Name: 1, Type: uint32(elf.SHT_PROGBITS), Off: 900, Size: 4, Addralign: 1})
			copy(input[900:], "user")
			for _, preserve := range []bool{false, true} {
				opts := SectionOptions{PreserveSectionNameTable: preserve}
				output, err := SetSection(context.Background(), input, ".new", nil, opts)
				if err != nil {
					t.Fatal(err)
				}
				replaced, err := SetSection(context.Background(), output, ".shstrtab", []byte("edit"), opts)
				if preserve {
					if err == nil || replaced != nil {
						t.Fatal("duplicate target accepted")
					}
				} else {
					if err != nil || len(openELF(t, output).Sections) != 7 {
						t.Fatalf("default add-then-replace regressed: %v", err)
					}
					got, err := openELF(t, replaced).Sections[5].Data()
					if err != nil || string(got) != "edit" {
						t.Fatalf("user section not replaced: %q %v", got, err)
					}
				}
			}
			input = sharedNamesFixture(t, enc, 5)
			for _, preserve := range []bool{false, true} {
				var dst bytes.Buffer
				err := WriteSection(context.Background(), &dst, bytes.NewReader(input), int64(len(input)), ".shstrtab", []byte("opaque"), SectionOptions{PreserveSectionNameTable: preserve})
				if preserve {
					if err == nil || dst.Len() != 0 {
						t.Fatal("contradictory target accepted")
					}
				} else if err != nil {
					t.Fatalf("default direct target regressed: %v", err)
				}
				var active bytes.Buffer
				err = WriteSection(context.Background(), &active, bytes.NewReader(input), int64(len(input)), ".strtab", nil, SectionOptions{PreserveSectionNameTable: preserve})
				if err == nil || active.Len() != 0 {
					t.Fatal("active table replacement accepted")
				}
			}
			if enc.class == elf.ELFCLASS32 {
				clear(input[32:36])
				clear(input[46:52])
			} else {
				clear(input[40:48])
				clear(input[58:64])
			}
			plain, err := SetSection(context.Background(), input, ".new", nil, SectionOptions{})
			if err != nil {
				t.Fatal(err)
			}
			preserved, err := SetSection(context.Background(), input, ".new", nil, SectionOptions{PreserveSectionNameTable: true})
			if err != nil || !bytes.Equal(plain, preserved) {
				t.Fatalf("sectionless output changed: %v", err)
			}
		})
	}
}

func TestPreserveNameTableBoundaries(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			for _, count := range []int{int(elf.SHN_LORESERVE) - 2, int(elf.SHN_LORESERVE) - 1, int(elf.SHN_LORESERVE)} {
				input := sharedNamesFixture(t, enc, count)
				output, err := SetSection(context.Background(), input, ".new", nil, SectionOptions{PreserveSectionNameTable: true})
				if err != nil {
					t.Fatal(err)
				}
				assertOriginalSections(t, enc, input, output)
				parsed, err := readFile(context.Background(), bytes.NewReader(output), int64(len(output)))
				if err != nil || len(parsed.sections) != count+2 || parsed.shstrndx < count {
					t.Fatalf("extended counts lost: %v", err)
				}
				if parsed.sections[0].Size != uint64(count+2) || (parsed.shstrndx >= int(elf.SHN_LORESERVE) && parsed.sections[0].Link != uint32(parsed.shstrndx)) {
					t.Fatal("extended count/index not encoded")
				}
			}
			input := sharedNamesFixture(t, enc, 5)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var dst bytes.Buffer
			err := WriteSection(ctx, &dst, bytes.NewReader(input), int64(len(input)), ".new", nil, SectionOptions{PreserveSectionNameTable: true})
			if !errors.Is(err, context.Canceled) || dst.Len() != 0 {
				t.Fatalf("canceled output: %v", err)
			}
			if enc.class == elf.ELFCLASS32 {
				err = WriteSection(context.Background(), &dst, sparseReader{input, math.MaxUint32}, math.MaxUint32, ".new", nil, SectionOptions{PreserveSectionNameTable: true})
				if err == nil || dst.Len() != 0 {
					t.Fatal("ELF32 overflow wrote output")
				}
			}
		})
	}
}
