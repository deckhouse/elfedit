package elfedit

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
)

func TestSectionZeroValidation(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			for _, s := range []elf.Section64{
				{Type: uint32(elf.SHT_PROGBITS)},
				{Name: 1}, {Flags: uint64(elf.SHF_COMPRESSED)}, {Addr: 1},
				{Off: 1}, {Addralign: 1}, {Entsize: 1},
				{Size: 1}, {Link: 1}, {Info: 1},
			} {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				putFixtureSection(t, enc, input, 0, s)
				var out bytes.Buffer
				err := WriteSection(context.Background(), &out, bytes.NewReader(input), int64(len(input)), ".extra", nil, SectionOptions{})
				if err == nil || out.Len() != 0 {
					t.Fatalf("accepted invalid section zero %+v: err=%v bytes=%d", s, err, out.Len())
				}
			}
		})
	}
}

func TestInactiveSections(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			for _, name := range []uint32{22, math.MaxUint32} {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				s := elf.Section64{Name: name, Flags: math.MaxUint32, Addr: math.MaxUint32, Off: math.MaxUint32, Size: math.MaxUint32, Link: math.MaxUint32, Info: math.MaxUint32, Addralign: math.MaxUint32, Entsize: math.MaxUint32}
				if enc.class == elf.ELFCLASS64 {
					s.Off, s.Size = math.MaxUint64, math.MaxUint64
				}
				putFixtureSection(t, enc, input, 4, s)
				out, err := SetSection(context.Background(), input, ".extra", []byte("data"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertPreserved(t, input, out)
				off, size := sectionTable(t, enc, out)
				if !bytes.Equal(input[1024+4*size:1024+5*size], out[off+4*size:off+5*size]) {
					t.Fatal("inactive header changed")
				}
				if len(out) != off+6*size {
					t.Fatal("inactive section was reused instead of appending")
				}
			}
		})
	}
}

func TestReplacementMetadata(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			input := fixture(t, enc, elf.EM_ARM, 5, false)
			putFixtureSection(t, enc, input, 4, elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Off: 640, Size: 8, Addralign: 8, Link: 1, Info: 2, Addr: 0x1234, Entsize: 8})
			before := openELF(t, input).Sections[4]
			out, err := SetSection(context.Background(), input, ".extra", []byte("replaced"), SectionOptions{})
			if err != nil {
				t.Fatal(err)
			}
			after := openELF(t, out)
			s := after.Sections[4]
			if len(after.Sections) != 5 || s.Name != before.Name || s.Link != before.Link || s.Info != before.Info || s.Addr != before.Addr || s.Entsize != before.Entsize {
				t.Fatalf("replacement lost metadata: %+v", s.SectionHeader)
			}
			data, err := s.Data()
			if err != nil || string(data) != "replaced" {
				t.Fatalf("replacement payload=%q err=%v", data, err)
			}
			assertSectionEditPreserved(t, input, out, ".extra")
			if len(out) != len(input) {
				t.Fatalf("same-sized replacement resized the file: %d -> %d", len(input), len(out))
			}
		})
	}
}

func TestReplaceInPlaceRejectsOverlaps(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			t.Run("section", func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 6, false)
				putFixtureSection(t, enc, input, 4, elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Off: 640, Size: 8, Addralign: 8})
				putFixtureSection(t, enc, input, 5, elf.Section64{Type: uint32(elf.SHT_PROGBITS), Off: 644, Size: 4, Addralign: 1})

				out, err := SetSection(context.Background(), input, ".extra", []byte("replaced"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertPreserved(t, input, out)
				if s := openELF(t, out).Section(".extra"); s.Offset < uint64(len(input)) {
					t.Fatalf("overlapping section was overwritten in place at %d", s.Offset)
				}
			})

			t.Run("section table", func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 6, false)
				putFixtureSection(t, enc, input, 4, elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Off: 640, Size: 8, Addralign: 8})
				putFixtureSection(t, enc, input, 5, elf.Section64{Type: uint32(elf.SHT_PROGBITS), Off: 1024, Size: 8, Addralign: 1})

				out, err := SetSection(context.Background(), input, ".extra", []byte("replaced"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertPreserved(t, input, out)
				if s := openELF(t, out).Section(".extra"); s.Offset < uint64(len(input)) {
					t.Fatalf("section sharing the table was overwritten in place at %d", s.Offset)
				}
			})

			t.Run("table inside a segment", func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				putFixtureSection(t, enc, input, 4, elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Off: 640, Size: 8, Addralign: 8})
				putFixtureSegment(t, enc, input, 1024, 64)

				out, err := SetSection(context.Background(), input, ".extra", []byte("replaced"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertPreserved(t, input, out)
				if s := openELF(t, out).Section(".extra"); s.Offset < uint64(len(input)) {
					t.Fatalf("section whose table lies in a segment was overwritten in place at %d", s.Offset)
				}
			})

			t.Run("ELF header", func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				putFixtureSection(t, enc, input, 4, elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Off: 8, Size: 8, Addralign: 1})

				out, err := SetSection(context.Background(), input, ".extra", []byte("replaced"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertPreserved(t, input, out)
				if s := openELF(t, out).Section(".extra"); s.Offset < uint64(len(input)) {
					t.Fatalf("section inside the ELF header was overwritten in place at %d", s.Offset)
				}
			})

			t.Run("program headers", func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				headerSize := uint64(64)
				if enc.class == elf.ELFCLASS32 {
					headerSize = 52
				}
				putFixtureSection(t, enc, input, 4, elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Off: headerSize, Size: 8, Addralign: 1})

				out, err := SetSection(context.Background(), input, ".extra", []byte("replaced"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertPreserved(t, input, out)
				if s := openELF(t, out).Section(".extra"); s.Offset < uint64(len(input)) {
					t.Fatalf("section overlapping program headers was overwritten in place at %d", s.Offset)
				}
			})
		})
	}
}

func TestExtendedProgramCount(t *testing.T) {
	for _, enc := range encodings {
		for _, count := range []uint32{0xffff, 0x10000} {
			t.Run(fmt.Sprintf("%s/%d", enc.name, count), func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				putFixtureSection(t, enc, input, 0, elf.Section64{Info: count})
				phoff := len(input)
				var segment any = elf.Prog64{Type: uint32(elf.PT_NOTE), Off: 256, Filesz: 29}
				if enc.class == elf.ELFCLASS32 {
					segment = elf.Prog32{Type: uint32(elf.PT_NOTE), Off: 256, Filesz: 29}
					enc.order.PutUint32(input[28:32], uint32(phoff))
					enc.order.PutUint16(input[44:46], 0xffff)
				} else {
					enc.order.PutUint64(input[32:40], uint64(phoff))
					enc.order.PutUint16(input[56:58], 0xffff)
				}
				phsize := binary.Size(segment)
				input = append(input, make([]byte, int(count)*phsize)...)
				out, err := SetSection(context.Background(), input, ".extra", []byte("data"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertPreserved(t, input, out)
				off, _ := sectionTable(t, enc, out)
				infoOffset := 44
				if enc.class == elf.ELFCLASS32 {
					infoOffset = 28
				}
				if got := enc.order.Uint32(out[off+infoOffset:]); got != count {
					t.Fatalf("extended program count=%d, want %d", got, count)
				}
				var p bytes.Buffer
				if err := binary.Write(&p, enc.order, segment); err != nil {
					t.Fatal(err)
				}
				copy(input[phoff+int(count-1)*phsize:], p.Bytes())
				var rejected bytes.Buffer
				err = WriteSection(context.Background(), &rejected, bytes.NewReader(input), int64(len(input)), ".extra", nil, SectionOptions{})
				if err == nil || rejected.Len() != 0 {
					t.Fatalf("last extended program segment ignored: err=%v bytes=%d", err, rejected.Len())
				}
			})
		}
	}
}

func TestOutputBudget(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			input := fixture(t, enc, elf.EM_ARM, 5, false)
			for range 2 {
				out, err := SetSection(context.Background(), input, ".extra", []byte("data"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				for _, limit := range []uint64{uint64(len(out)) - 1, uint64(len(out))} {
					var limited bytes.Buffer
					err := WriteSection(context.Background(), &limited, bytes.NewReader(input), int64(len(input)), ".extra", []byte("data"), SectionOptions{MaxOutputSize: limit})
					if limit < uint64(len(out)) {
						if err == nil || limited.Len() != 0 {
							t.Fatalf("budget exceeded: err=%v bytes=%d", err, limited.Len())
						}
					} else if err != nil || !bytes.Equal(limited.Bytes(), out) {
						t.Fatalf("exact budget rejected: %v", err)
					}
				}
				input = out
			}
			for _, names := range []bool{false, true} {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				opts := SectionOptions{Alignment: 1 << 28, MaxOutputSize: 4096}
				if names {
					putFixtureSection(t, enc, input, 1, elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: 256, Size: 29, Addralign: 1 << 28})
					opts.Alignment = 1
				}
				var out bytes.Buffer
				err := WriteSection(context.Background(), &out, bytes.NewReader(input), int64(len(input)), ".extra", nil, opts)
				if err == nil || out.Len() != 0 {
					t.Fatalf("alignment amplification accepted: err=%v bytes=%d", err, out.Len())
				}
			}
		})
	}
}

func TestCompressedPayload(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			input := fixture(t, enc, elf.EM_ARM, 5, false)
			payload := []byte("caller-encoded compressed bytes")
			var encoded bytes.Buffer
			var header any = elf.Chdr64{Type: uint32(elf.COMPRESS_ZLIB), Size: uint64(len(payload)), Addralign: 1}
			if enc.class == elf.ELFCLASS32 {
				header = elf.Chdr32{Type: uint32(elf.COMPRESS_ZLIB), Size: uint32(len(payload)), Addralign: 1}
			}
			if err := binary.Write(&encoded, enc.order, header); err != nil {
				t.Fatal(err)
			}
			z := zlib.NewWriter(&encoded)
			if _, err := z.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				out, err := SetSection(context.Background(), input, ".compressed", encoded.Bytes(), SectionOptions{Flags: elf.SHF_COMPRESSED, Alignment: 8})
				if err != nil {
					t.Fatal(err)
				}
				s := openELF(t, out).Section(".compressed")
				if s == nil || s.Flags&elf.SHF_COMPRESSED == 0 {
					t.Fatal("missing compressed section")
				}
				data, err := s.Data()
				if err != nil || !bytes.Equal(data, payload) || !bytes.Equal(out[s.Offset:s.Offset+s.FileSize], encoded.Bytes()) {
					t.Fatalf("compressed payload did not round-trip: %q err=%v", data, err)
				}
				assertPreserved(t, input, out)
				input = out
			}
			input = fixture(t, enc, elf.EM_ARM, 5, false)
			putFixtureSection(t, enc, input, 1, elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Flags: uint64(elf.SHF_COMPRESSED), Off: 256, Size: 29, Addralign: 1})
			var out bytes.Buffer
			err := WriteSection(context.Background(), &out, bytes.NewReader(input), int64(len(input)), ".extra", nil, SectionOptions{})
			if err == nil || out.Len() != 0 {
				t.Fatalf("compressed names interpreted as plain strings: err=%v bytes=%d", err, out.Len())
			}
		})
	}
}

func TestInterruptedOutput(t *testing.T) {
	for _, stage := range []string{"body", "padding"} {
		t.Run(stage, func(t *testing.T) {
			for _, fail := range []bool{false, true} {
				input := fixture(t, encodings[2], elf.EM_AARCH64, 5, false)
				opts := SectionOptions{}
				if stage == "body" {
					input = append(input, make([]byte, 256*1024)...)
				} else {
					opts.Alignment = 1 << 20
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				w := interruptWriter{after: 64 * 1024, interrupt: cancel}
				want := error(context.Canceled)
				if fail {
					w.err, want = io.ErrClosedPipe, io.ErrClosedPipe
				}
				err := WriteSection(ctx, &w, bytes.NewReader(input), int64(len(input)), ".extra", nil, opts)
				if !errors.Is(err, want) || w.bytes > w.after+64*1024 {
					t.Fatalf("output did not stop promptly: err=%v bytes=%d", err, w.bytes)
				}
			}
		})
	}
}

func TestAppendedReplacementMetadata(t *testing.T) {
	for _, enc := range encodings {
		for _, align := range []uint64{1, 2048} {
			t.Run(fmt.Sprintf("%s/align%d", enc.name, align), func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				original := elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_LINK_ORDER | elf.SHF_INFO_LINK), Off: 640, Size: 8, Link: 2, Info: 3, Entsize: 8, Addralign: 8}
				putFixtureSection(t, enc, input, 4, original)
				payload := bytes.Repeat([]byte{7}, 16)
				if align == 2048 {
					payload = payload[:8]
				}
				opts := SectionOptions{Flags: elf.SHF_LINK_ORDER | elf.SHF_INFO_LINK, Alignment: align}
				out, err := SetSection(context.Background(), input, ".extra", payload, opts)
				if err != nil {
					t.Fatal(err)
				}
				var streamed bytes.Buffer
				if err := WriteSection(context.Background(), &streamed, bytes.NewReader(input), int64(len(input)), ".extra", payload, opts); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out, streamed.Bytes()) {
					t.Fatal("APIs differ")
				}
				after := openELF(t, out).Sections[4]
				if after.Offset < uint64(len(input)) {
					t.Fatal("fixture did not force append")
				}
				if after.Link != original.Link || after.Info != original.Info || after.Entsize != original.Entsize || after.Addr != original.Addr {
					t.Fatalf("appended replacement lost metadata: %+v", after.SectionHeader)
				}
				assertPreserved(t, input, out)
				again, err := SetSection(context.Background(), out, ".extra", payload, opts)
				if err != nil || !bytes.Equal(again, out) {
					t.Fatalf("same-size repeat changed bytes: %v", err)
				}
			})
		}
	}
}

func TestUnusedProgramHeaders(t *testing.T) {
	for _, enc := range encodings {
		for _, off := range []uint64{256, 640, 1024, math.MaxUint32} {
			t.Run(fmt.Sprintf("%s/%d", enc.name, off), func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				putFixtureSection(t, enc, input, 4, elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Off: 640, Size: 8, Addralign: 1})
				var p bytes.Buffer
				phoff := 64
				if enc.class == elf.ELFCLASS32 {
					phoff = 52
					enc.order.PutUint16(input[44:46], 2)
					if err := binary.Write(&p, enc.order, elf.Prog32{Type: uint32(elf.PT_NULL), Flags: 7, Off: uint32(off), Filesz: 29}); err != nil {
						t.Fatal(err)
					}
				} else {
					enc.order.PutUint16(input[56:58], 2)
					if off == math.MaxUint32 {
						off = math.MaxUint64
					}
					if err := binary.Write(&p, enc.order, elf.Prog64{Type: uint32(elf.PT_NULL), Flags: 7, Off: off, Filesz: 29}); err != nil {
						t.Fatal(err)
					}
				}
				copy(input[phoff+p.Len():], p.Bytes())
				for _, name := range []string{".new", ".extra"} {
					out, err := SetSection(context.Background(), input, name, []byte("replaced"), SectionOptions{})
					if err != nil {
						t.Fatal(err)
					}
					assertSectionEditPreserved(t, input, out, name)
					if name == ".extra" && len(out) != len(input) {
						t.Fatal("unused geometry prevented in-place replacement")
					}
					var streamed bytes.Buffer
					if err := WriteSection(context.Background(), &streamed, bytes.NewReader(input), int64(len(input)), name, []byte("replaced"), SectionOptions{}); err != nil || !bytes.Equal(streamed.Bytes(), out) {
						t.Fatalf("streaming differs: %v", err)
					}
				}
				// The same out-of-file geometry on a real segment must still fail.
				if off >= math.MaxUint32 {
					enc.order.PutUint32(input[phoff+p.Len():], uint32(elf.PT_LOAD))
					var dst bytes.Buffer
					if err := WriteSection(context.Background(), &dst, bytes.NewReader(input), int64(len(input)), ".new", nil, SectionOptions{}); err == nil || dst.Len() != 0 {
						t.Fatal("accepted real segment outside file")
					}
				}
			})
		}
	}
}

func TestUnusedProgramTableProtection(t *testing.T) {
	for _, enc := range encodings {
		for _, tableAlias := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/table=%v", enc.name, tableAlias), func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				phoff := 64
				if enc.class == elf.ELFCLASS32 {
					phoff = 52
				}
				targetOff := uint64(phoff)
				enc.order.PutUint32(input[phoff:], uint32(elf.PT_NULL))
				if tableAlias {
					targetOff = 640
					if enc.class == elf.ELFCLASS32 {
						enc.order.PutUint32(input[28:32], 1024)
					} else {
						enc.order.PutUint64(input[32:40], 1024)
					}
				}
				putFixtureSection(t, enc, input, 4, elf.Section64{Name: 22, Type: uint32(elf.SHT_PROGBITS), Off: targetOff, Size: 8, Addralign: 1})
				out, err := SetSection(context.Background(), input, ".extra", []byte("replaced"), SectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				assertPreserved(t, input, out)
				if openELF(t, out).Section(".extra").Offset < uint64(len(input)) {
					t.Fatal("overwrote physical program table")
				}
			})
		}
	}
}
