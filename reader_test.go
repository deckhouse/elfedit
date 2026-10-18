package elfedit

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"testing"
)

type endEOFReader struct{ data []byte }

func (r endEOFReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := bytes.NewReader(r.data).ReadAt(p, off)
	if off+int64(n) == int64(len(r.data)) {
		err = io.EOF
	}
	return n, err
}

func TestReaderAtFinalEOF(t *testing.T) {
	for _, enc := range encodings {
		t.Run(enc.name, func(t *testing.T) {
			t.Run("header-only", func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				if enc.class == elf.ELFCLASS32 {
					input = input[:52]
					enc.order.PutUint32(input[28:32], 0)
					enc.order.PutUint32(input[32:36], 0)
					enc.order.PutUint16(input[44:46], 0)
					enc.order.PutUint16(input[48:50], 0)
					enc.order.PutUint16(input[50:52], 0)
				} else {
					input = input[:64]
					enc.order.PutUint64(input[32:40], 0)
					enc.order.PutUint64(input[40:48], 0)
					enc.order.PutUint16(input[56:58], 0)
					enc.order.PutUint16(input[60:62], 0)
					enc.order.PutUint16(input[62:64], 0)
				}
				compareEOFReaders(t, input)
			})
			t.Run("names-at-EOF", func(t *testing.T) {
				input := fixture(t, enc, elf.EM_ARM, 5, false)
				f, err := readFile(context.Background(), bytes.NewReader(input), int64(len(input)))
				if err != nil {
					t.Fatal(err)
				}
				s := f.sections[f.shstrndx]
				names := bytes.Clone(input[s.Off : s.Off+s.Size])
				s.Off = uint64(len(input))
				input = append(input, names...)
				putFixtureSection(t, enc, input, f.shstrndx, s)
				compareEOFReaders(t, input)
			})
		})
	}
}

func compareEOFReaders(t *testing.T, input []byte) {
	t.Helper()
	want, err := SetSection(context.Background(), input, ".audit", []byte("data"), SectionOptions{})
	if err != nil {
		t.Fatal("control:", err)
	}
	var got bytes.Buffer
	err = WriteSection(context.Background(), &got, endEOFReader{input}, int64(len(input)), ".audit", []byte("data"), SectionOptions{})
	if err != nil {
		t.Fatal("legal ReaderAt:", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("ReaderAt choice changed output")
	}
}

type faultReader struct {
	data   []byte
	offset int64
	length int
	short  bool
	fault  error
}

func (r faultReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := bytes.NewReader(r.data).ReadAt(p, off)
	if off == r.offset && len(p) == r.length {
		if r.short {
			return n - 1, r.fault
		}
		return n, r.fault
	}
	return n, err
}

func TestReaderAtFailures(t *testing.T) {
	for _, enc := range encodings {
		input := fixture(t, enc, elf.EM_ARM, 5, false)
		f, err := readFile(context.Background(), bytes.NewReader(input), int64(len(input)))
		if err != nil {
			t.Fatal(err)
		}
		names := f.sections[f.shstrndx]
		for _, at := range []struct {
			off  int64
			size int
		}{{0, 16}, {0, len(f.header)}, {int64(names.Off), int(names.Size)}} {
			for _, short := range []bool{false, true} {
				for _, failure := range []error{io.ErrClosedPipe, io.EOF, nil} {
					if !short && (failure == io.EOF || failure == nil) {
						continue
					}
					t.Run(fmt.Sprintf("%s/off%d/len%d/short%v/%v", enc.name, at.off, at.size, short, failure), func(t *testing.T) {
						var out bytes.Buffer
						err := WriteSection(context.Background(), &out, faultReader{input, at.off, at.size, short, failure}, int64(len(input)), ".audit", []byte("data"), SectionOptions{})
						if failure == io.ErrClosedPipe && !errors.Is(err, failure) {
							t.Fatalf("lost read error: %v", err)
						}
						if short && failure == nil && !errors.Is(err, io.ErrUnexpectedEOF) {
							t.Fatalf("short nil read: %v, want io.ErrUnexpectedEOF", err)
						}
						if err == nil || out.Len() != 0 {
							t.Fatalf("encoding=%s off=%d len=%d short=%v fault=%v: err=%v output=%d", enc.name, at.off, at.size, short, failure, err, out.Len())
						}
					})
				}
			}
		}
	}
}
