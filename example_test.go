package elfedit_test

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/deckhouse/elfedit"
)

func ExampleSetSection() {
	image := make([]byte, 64)
	copy(image, "\x7fELF")
	image[4], image[5], image[6] = 2, 1, 1
	binary.LittleEndian.PutUint32(image[20:24], 1)
	binary.LittleEndian.PutUint16(image[52:54], 64)
	output, err := elfedit.SetSection(context.Background(), image, ".metadata", []byte("hello"), elfedit.SectionOptions{Type: elf.SHT_PROGBITS, Alignment: 8})
	if err != nil {
		panic(err)
	}
	f, err := elf.NewFile(bytes.NewReader(output))
	if err != nil {
		panic(err)
	}
	data, err := f.Section(".metadata").Data()
	if err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}
	fmt.Println(string(data))
	// Output: hello
}
