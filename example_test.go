package elfedit_test

import (
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
	fmt.Println(len(output) > len(image), err)
	// Output: true <nil>
}
