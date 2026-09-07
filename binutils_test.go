package elfedit

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBinutils(t *testing.T) {
	if os.Getenv("ELFEDIT_BINUTILS") != "1" {
		t.Skip("run task test:binutils with GNU objcopy/readelf and clang")
	}
	for _, tool := range []string{"clang", "objcopy", "readelf"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"i386-linux-gnu", "x86_64-linux-gnu", "arm-linux-gnueabi", "armeb-linux-gnueabi", "aarch64-linux-gnu", "aarch64_be-linux-gnu"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			inputPath, payloadPath, outputPath := filepath.Join(dir, "input.o"), filepath.Join(dir, "payload"), filepath.Join(dir, "output.o")
			runTool(t, "clang", "-target", target, "-g", "-c", "testdata/example.c", "-o", inputPath)
			input, err := os.ReadFile(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			f := openELF(t, input)
			payload := notePayload(f.ByteOrder)
			if err := os.WriteFile(payloadPath, payload, 0600); err != nil {
				t.Fatal(err)
			}
			ours, err := SetSection(context.Background(), input, ".note.example", payload, SectionOptions{Type: elf.SHT_NOTE, Alignment: 4})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(outputPath, ours, 0600); err != nil {
				t.Fatal(err)
			}
			header := runTool(t, "readelf", "-SW", outputPath)
			if !strings.Contains(header, ".note.example") {
				t.Fatal("readelf did not find added section")
			}
			notes := runTool(t, "readelf", "-n", outputPath)
			if !strings.Contains(notes, "example") {
				t.Fatal("readelf did not recognize note owner")
			}
			dumped := filepath.Join(dir, "dumped")
			runTool(t, "objcopy", "--dump-section", ".note.example="+dumped, outputPath, filepath.Join(dir, "copied.o"))
			got, err := os.ReadFile(dumped)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("objcopy reads different payload")
			}
			gnuPath := filepath.Join(dir, "gnu.o")
			runTool(t, "objcopy", "--add-section", ".note.example="+payloadPath, "--set-section-flags", ".note.example=n", inputPath, gnuPath)
			gnu, err := os.ReadFile(gnuPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range [][]byte{ours, gnu} {
				updated, err := SetSection(context.Background(), source, ".note.example", payload, SectionOptions{Type: elf.SHT_NOTE, Alignment: 4})
				if err != nil {
					t.Fatal(err)
				}
				before, after := openELF(t, source), openELF(t, updated)
				if len(before.Sections) != len(after.Sections) {
					t.Fatal("replacement changed section count")
				}
				if err := os.WriteFile(outputPath, updated, 0600); err != nil {
					t.Fatal(err)
				}
				runTool(t, "readelf", "-SW", outputPath)
			}
		})
	}
}

func TestLinuxExecution(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("run task test:linux for execution validation")
	}
	input, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	file := openELF(t, input)
	output, err := SetSection(context.Background(), input, ".note.example", notePayload(file.ByteOrder), SectionOptions{Type: elf.SHT_NOTE, Alignment: 4})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "true")
	if err := os.WriteFile(path, output, 0700); err != nil {
		t.Fatal(err)
	}
	runTool(t, path)
}

func notePayload(order binary.ByteOrder) []byte {
	data := make([]byte, 24)
	order.PutUint32(data[:4], 8)
	order.PutUint32(data[4:8], 4)
	order.PutUint32(data[8:12], 1)
	copy(data[12:], "example\x00")
	copy(data[20:], "data")
	return data
}

func runTool(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}
