package elfedit

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
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
			assertPreserved(t, input, out)
		})
	}
}

func TestExtendedProgramCount(t *testing.T) {
	const count = 0x10000
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
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
			input = append(input, make([]byte, count*phsize)...)
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
			copy(input[phoff+(count-1)*phsize:], p.Bytes())
			var rejected bytes.Buffer
			err = WriteSection(context.Background(), &rejected, bytes.NewReader(input), int64(len(input)), ".extra", nil, SectionOptions{})
			if err == nil || rejected.Len() != 0 {
				t.Fatalf("last extended program segment ignored: err=%v bytes=%d", err, rejected.Len())
			}
		})
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
