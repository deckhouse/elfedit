package elfedit

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"testing"
)

func TestSetSection(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			for _, machine := range []elf.Machine{elf.EM_386, elf.EM_X86_64, elf.EM_ARM, elf.EM_AARCH64, elf.EM_MIPS, elf.EM_PPC, elf.EM_PPC64, elf.EM_S390, elf.EM_RISCV, elf.EM_SPARCV9, elf.EM_LOONGARCH, 0xbeef} {
				t.Run(machine.String(), func(t *testing.T) {
					original := fixture(t, enc, machine, 5, false)
					before := openELF(t, original)
					opts := SectionOptions{Type: elf.SHT_NOTE, Flags: elf.SHF_WRITE, Alignment: 32}
					for _, payload := range [][]byte{[]byte("opaque bytes"), bytes.Repeat([]byte{7}, 999), {}, []byte("last")} {
						pristine := bytes.Clone(original)
						out, err := SetSection(context.Background(), original, ".note.example", payload, opts)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(original, pristine) {
							t.Fatal("input mutated")
						}
						assertPreserved(t, original, out)
						after := openELF(t, out)
						section := after.Section(".note.example")
						if section == nil || section.Type != opts.Type || section.Flags != opts.Flags || section.Addralign != opts.Alignment || section.Offset%opts.Alignment != 0 {
							t.Fatalf("wrong section metadata: %+v", section)
						}
						data, err := section.Data()
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(data, payload) {
							t.Fatal("section payload differs")
						}
						if len(after.Sections) != 6 {
							t.Fatalf("section count grew: %d", len(after.Sections))
						}
						if !reflect.DeepEqual(after.FileHeader, before.FileHeader) {
							t.Fatal("ELF identity or entry point changed")
						}
						if !reflect.DeepEqual(after.Progs[0].ProgHeader, before.Progs[0].ProgHeader) {
							t.Fatal("program header changed")
						}
						for _, i := range []int{2, 3, 4} {
							if !reflect.DeepEqual(after.Sections[i].SectionHeader, before.Sections[i].SectionHeader) {
								t.Fatalf("section %d header changed", i)
							}
						}
						if after.Sections[1].Offset%after.Sections[1].Addralign != 0 {
							t.Fatal("string table lost alignment")
						}
						original = out
					}
				})
			}
		})
	}
}

func TestExtendedNumbering(t *testing.T) {
	for _, enc := range encodings {
		for _, count := range []int{int(elf.SHN_LORESERVE) - 1, int(elf.SHN_LORESERVE) + 1} {
			t.Run(enc.name+"/"+strconv.Itoa(count), func(t *testing.T) {
				input := fixture(t, enc, elf.EM_RISCV, count, true)
				out, err := SetSection(context.Background(), input, ".extra", []byte("x"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				f := openELF(t, out)
				if len(f.Sections) != count+1 || f.Sections[count].Name != ".extra" {
					t.Fatal("extended numbering lost section")
				}
				var tableOffset uint64
				var num, names uint16
				if enc.class == elf.ELFCLASS32 {
					tableOffset = uint64(enc.order.Uint32(out[32:36]))
					num = enc.order.Uint16(out[48:50])
					names = enc.order.Uint16(out[50:52])
					if !bytes.Equal(input[20:24], out[20:24]) {
						t.Fatal("ELF32 version overwritten")
					}
				} else {
					tableOffset = enc.order.Uint64(out[40:48])
					num = enc.order.Uint16(out[60:62])
					names = enc.order.Uint16(out[62:64])
				}
				if num != 0 {
					t.Fatal("e_shnum should use extended count at SHN_LORESERVE")
				}
				if count-1 >= int(elf.SHN_LORESERVE) && names != uint16(elf.SHN_XINDEX) {
					t.Fatal("missing extended name-table index")
				}
				if tableOffset <= uint64(len(input)) {
					t.Fatal("table not appended")
				}
			})
		}
	}
}

func TestSectionless(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			input := fixture(t, enc, elf.EM_MIPS, 5, false)
			if enc.class == elf.ELFCLASS32 {
				clear(input[32:36])
				clear(input[46:52])
			} else {
				clear(input[40:48])
				clear(input[58:64])
			}
			out, err := SetSection(context.Background(), input, ".extra", []byte("metadata"), SectionOptions{})
			if err != nil {
				t.Fatal(err)
			}
			f := openELF(t, out)
			if len(f.Sections) != 3 || f.Section(".extra") == nil {
				t.Fatal("section table not created")
			}
		})
	}
}

func TestRejectMalformed(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			input := fixture(t, enc, elf.EM_ARM, 5, false)
			for i := 0; i < 64; i++ {
				if _, err := SetSection(context.Background(), input[:i], ".extra", []byte("x"), SectionOptions{}); err == nil {
					t.Fatalf("accepted truncated header %d", i)
				}
			}
			for _, tc := range []struct {
				name   string
				change func([]byte)
			}{
				{"magic", func(b []byte) { b[0] = 0 }},
				{"version", func(b []byte) { b[6] = 0 }},
				{"data", func(b []byte) { b[5] = 9 }},
				{"names", func(b []byte) { b[256] = 1 }},
				{"overflow", func(b []byte) {
					if enc.class == elf.ELFCLASS32 {
						enc.order.PutUint16(b[48:50], 0)
						enc.order.PutUint32(b[1024+20:], math.MaxUint32)
					} else {
						enc.order.PutUint16(b[60:62], 0)
						enc.order.PutUint64(b[1024+32:], math.MaxUint64/64+1)
					}
				}},
				{"segment", func(b []byte) {
					if enc.class == elf.ELFCLASS32 {
						enc.order.PutUint32(b[52+16:], math.MaxUint32)
					} else {
						enc.order.PutUint64(b[64+32:], math.MaxUint64)
					}
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					b := bytes.Clone(input)
					tc.change(b)
					var out bytes.Buffer
					err := WriteSection(context.Background(), &out, bytes.NewReader(b), int64(len(b)), ".extra", []byte("x"), SectionOptions{})
					if err == nil || out.Len() != 0 {
						t.Fatalf("malformed input written: err=%v bytes=%d", err, out.Len())
					}
				})
			}
		})
	}
}

func TestRejectUnsafeChanges(t *testing.T) {
	input := fixture(t, encodings[2], elf.EM_X86_64, 5, false)
	for _, tc := range []struct {
		name string
		opts SectionOptions
	}{
		{".text", SectionOptions{}}, {".bss", SectionOptions{}}, {".shstrtab", SectionOptions{}}, {"", SectionOptions{}}, {"bad\x00name", SectionOptions{}},
		{".extra", SectionOptions{Flags: elf.SHF_ALLOC}}, {".extra", SectionOptions{Type: elf.SHT_NOBITS}}, {".extra", SectionOptions{Alignment: 3}},
		{".extra", SectionOptions{Alignment: 1 << 63}},
	} {
		if _, err := SetSection(context.Background(), input, tc.name, []byte("x"), tc.opts); err == nil {
			t.Fatalf("accepted unsafe change %q %+v", tc.name, tc.opts)
		}
	}
	b := bytes.Clone(input)
	binary.LittleEndian.PutUint64(b[1024+64*2+8:], 0)
	if _, err := SetSection(context.Background(), b, ".text", []byte("x"), SectionOptions{}); err == nil {
		t.Fatal("accepted section inside segment without SHF_ALLOC")
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write(p []byte) (int, error) { return 0, w.err }

var _ io.Writer = failingWriter{}

func TestIOAndCancellation(t *testing.T) {
	input := fixture(t, encodings[0], elf.EM_386, 5, false)
	for _, failure := range []error{io.ErrClosedPipe, nil} {
		err := WriteSection(context.Background(), failingWriter{failure}, bytes.NewReader(input), int64(len(input)), ".extra", []byte("x"), SectionOptions{})
		want := failure
		if want == nil {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SetSection(ctx, input, ".extra", []byte("x"), SectionOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
	var out bytes.Buffer
	if err := WriteSection(context.Background(), &out, bytes.NewReader(input), int64(len(input))+1024, ".extra", []byte("x"), SectionOptions{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("source failure = %v", err)
	}
}

func FuzzSetSection(f *testing.F) {
	for _, enc := range encodings {
		f.Add(fixture(f, enc, elf.EM_ARM, 5, false))
		inactive := fixture(f, enc, elf.EM_ARM, 5, false)
		copy(inactive[256+22:], []byte(".fuzz\x00"))
		putFixtureSection(f, enc, inactive, 4, elf.Section64{Name: 22})
		f.Add(inactive)
	}
	f.Add([]byte("not ELF"))
	f.Fuzz(func(t *testing.T, input []byte) {
		out, err := SetSection(context.Background(), input, ".fuzz", []byte("data"), SectionOptions{MaxOutputSize: uint64(len(input)) + 1<<20})
		if err != nil {
			return
		}
		assertPreserved(t, input, out)
		// The editor preserves opaque metadata that debug/elf may reject already
		// in the input (e.g. undefined fields of inactive SHT_NULL entries).
		before, err := elf.NewFile(bytes.NewReader(input))
		if err != nil {
			return
		}
		if err := before.Close(); err != nil {
			t.Fatal(err)
		}
		file := openELF(t, out)
		var section *elf.Section
		for _, candidate := range file.Sections {
			if candidate.Type != elf.SHT_NULL && candidate.Name == ".fuzz" {
				section = candidate
				break
			}
		}
		if section == nil {
			t.Fatal("missing section")
		}
		data, err := section.Data()
		if err != nil || string(data) != "data" {
			t.Fatalf("payload=%q err=%v", data, err)
		}
	})
}

type sparseReader struct {
	prefix []byte
	size   int64
}

var _ io.ReaderAt = sparseReader{}

func (r sparseReader) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > 64*1024 {
		return 0, fmt.Errorf("read exceeds streaming buffer")
	}
	if off < 0 || off > r.size || int64(len(p)) > r.size-off {
		return 0, io.EOF
	}
	clear(p)
	if off < int64(len(r.prefix)) {
		copy(p, r.prefix[off:])
	}
	return len(p), nil
}

func TestStreamingAndELF32Overflow(t *testing.T) {
	input := fixture(t, encodings[2], elf.EM_AARCH64, 5, false)
	const size = 600 * 1024 * 1024
	source := sparseReader{input, size}
	out := streamVerifier{source: source}
	if err := WriteSection(context.Background(), &out, source, size, ".extra", []byte("data"), SectionOptions{}); err != nil {
		t.Fatal(err)
	}
	if out.bytes <= size || out.bytes > size+4096 {
		t.Fatalf("unexpected output size %d", out.bytes)
	}
	if !bytes.HasPrefix(out.tail.Bytes(), []byte("data")) {
		t.Fatal("streamed payload differs")
	}
	input = fixture(t, encodings[0], elf.EM_ARM, 5, false)
	var buffer bytes.Buffer
	err := WriteSection(context.Background(), &buffer, sparseReader{input, math.MaxUint32}, math.MaxUint32, ".extra", []byte("data"), SectionOptions{})
	if err == nil || buffer.Len() != 0 {
		t.Fatal("ELF32 overflow not rejected before writing")
	}
}

func TestDuplicateSectionAndNameTableInSegment(t *testing.T) {
	input := fixture(t, encodings[2], elf.EM_AARCH64, 5, false)
	binary.LittleEndian.PutUint32(input[1024+64*4:], 11)
	if _, err := SetSection(context.Background(), input, ".text", []byte("x"), SectionOptions{}); err == nil {
		t.Fatal("duplicate section accepted")
	}
	input = fixture(t, encodings[2], elf.EM_AARCH64, 5, false)
	binary.LittleEndian.PutUint64(input[64+8:], 256)
	binary.LittleEndian.PutUint64(input[64+32:], 32)
	if _, err := SetSection(context.Background(), input, ".extra", []byte("x"), SectionOptions{}); err == nil {
		t.Fatal("section-name table in program segment relocated")
	}
}
