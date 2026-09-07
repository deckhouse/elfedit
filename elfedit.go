// Package elfedit adds or replaces non-allocated ELF sections without relocating
// existing sections or segments. It supports ELF32/ELF64 and both byte orders.
package elfedit

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
)

type SectionOptions struct {
	// Zero Type means SHT_PROGBITS. Zero Alignment means byte alignment.
	Type      elf.SectionType
	Flags     elf.SectionFlag
	Alignment uint64
}

// SetSection adds or replaces name with opaque data and the supplied metadata.
// Replacing a section preserves its index, Link, Info, Addr and Entsize. Existing
// source bytes are retained except for the ELF header's section-table fields.
func SetSection(ctx context.Context, image []byte, name string, data []byte, opts SectionOptions) ([]byte, error) {
	var out bytes.Buffer
	if err := WriteSection(ctx, &out, bytes.NewReader(image), int64(len(image)), name, data, opts); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// WriteSection streams the result to dst. src must remain stable and must not
// alias dst: use a distinct output file, not an in-place write. Metadata is
// validated before writing; an I/O error may still leave partial output. Memory
// scales with section metadata, names and data, rather than the input file size.
// Allocated sections and sections overlapping segments cannot be moved.
func WriteSection(ctx context.Context, dst io.Writer, src io.ReaderAt, size int64, name string, data []byte, opts SectionOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dst == nil || src == nil {
		return fmt.Errorf("edit ELF: source and destination required")
	}
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return fmt.Errorf("edit ELF: section name must be nonempty and contain no NUL")
	}
	if opts.Type == 0 {
		opts.Type = elf.SHT_PROGBITS
	}
	if opts.Type == elf.SHT_NOBITS {
		return fmt.Errorf("edit ELF: SHT_NOBITS cannot contain file data")
	}
	if opts.Flags&elf.SHF_ALLOC != 0 {
		return fmt.Errorf("edit ELF: allocated sections are unsupported")
	}
	if opts.Alignment == 0 {
		opts.Alignment = 1
	}
	if opts.Alignment&(opts.Alignment-1) != 0 {
		return fmt.Errorf("edit ELF: alignment must be a power of two")
	}
	f, err := readFile(ctx, src, size)
	if err != nil {
		return err
	}
	index := -1
	for i, s := range f.sections {
		if i == 0 {
			continue
		}
		end := bytes.IndexByte(f.names[s.Name:], 0)
		if string(f.names[int(s.Name):int(s.Name)+end]) != name {
			continue
		}
		if index >= 0 {
			return fmt.Errorf("edit ELF: ambiguous duplicate section %q", name)
		}
		index = i
	}
	if index == f.shstrndx {
		return fmt.Errorf("edit ELF: cannot replace the section-name table")
	}
	if index >= 0 {
		if err := f.movable(f.sections[index]); err != nil {
			return fmt.Errorf("replace %q: %w", name, err)
		}
	} else {
		if err := f.movable(f.sections[f.shstrndx]); err != nil {
			return fmt.Errorf("extend section names: %w", err)
		}
	}
	limit := uint64(math.MaxInt64)
	if f.class == elf.ELFCLASS32 {
		limit = math.MaxUint32
	}
	offset, end, err := place(uint64(size), uint64(len(data)), opts.Alignment, limit)
	if err != nil {
		return err
	}
	var newNames []byte
	var namesOffset uint64
	if index < 0 {
		if uint64(len(f.names))+uint64(len(name))+1 > math.MaxUint32 {
			return fmt.Errorf("edit ELF: section names exceed 32 bits")
		}
		index = len(f.sections)
		f.sections = append(f.sections, elf.Section64{Name: uint32(len(f.names))})
		newNames = append(bytes.Clone(f.names), name...)
		newNames = append(newNames, 0)
		namesAlignment := max(f.sections[f.shstrndx].Addralign, 1)
		if namesAlignment&(namesAlignment-1) != 0 {
			return fmt.Errorf("edit ELF: invalid section-name alignment")
		}
		namesOffset, end, err = place(end, uint64(len(newNames)), namesAlignment, limit)
		if err != nil {
			return err
		}
		f.sections[f.shstrndx].Off = namesOffset
		f.sections[f.shstrndx].Size = uint64(len(newNames))
	}
	s := &f.sections[index]
	s.Type, s.Flags, s.Addralign = uint32(opts.Type), uint64(opts.Flags), opts.Alignment
	s.Off, s.Size = offset, uint64(len(data))
	shoff, _, err := place(end, uint64(len(f.sections))*uint64(f.shentsize), uint64(f.wordSize()), limit)
	if err != nil {
		return err
	}
	table, err := f.encodeTable(shoff)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeAll(dst, f.header); err != nil {
		return fmt.Errorf("write ELF header: %w", err)
	}
	if err := copyBytes(ctx, dst, io.NewSectionReader(src, int64(len(f.header)), size-int64(len(f.header))), size-int64(len(f.header))); err != nil {
		return fmt.Errorf("copy ELF body: %w", err)
	}
	if err := writeZeros(ctx, dst, offset-uint64(size)); err != nil {
		return err
	}
	if err := copyBytes(ctx, dst, bytes.NewReader(data), int64(len(data))); err != nil {
		return fmt.Errorf("write section data: %w", err)
	}
	position := offset + uint64(len(data))
	if newNames != nil {
		if err := writeZeros(ctx, dst, namesOffset-position); err != nil {
			return err
		}
		if err := writeAll(dst, newNames); err != nil {
			return fmt.Errorf("write section names: %w", err)
		}
		position = namesOffset + uint64(len(newNames))
	}
	if err := writeZeros(ctx, dst, shoff-position); err != nil {
		return err
	}
	if err := writeAll(dst, table); err != nil {
		return fmt.Errorf("write section headers: %w", err)
	}
	return ctx.Err()
}

type file struct {
	header    []byte
	class     elf.Class
	order     binary.ByteOrder
	shentsize int
	shstrndx  int
	sections  []elf.Section64
	names     []byte
	segments  []span
}

type span struct{ offset, size uint64 }

func readFile(ctx context.Context, src io.ReaderAt, size int64) (*file, error) {
	if size < 16 {
		return nil, fmt.Errorf("read ELF: truncated identification")
	}
	ident := make([]byte, 16)
	if _, err := src.ReadAt(ident, 0); err != nil {
		return nil, fmt.Errorf("read ELF identification: %w", err)
	}
	if string(ident[:4]) != elf.ELFMAG || ident[elf.EI_VERSION] != byte(elf.EV_CURRENT) {
		return nil, fmt.Errorf("read ELF: invalid magic or version")
	}
	f := &file{class: elf.Class(ident[elf.EI_CLASS])}
	switch elf.Data(ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		f.order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		f.order = binary.BigEndian
	default:
		return nil, fmt.Errorf("read ELF: unsupported byte order")
	}
	var shoff, phoff, shnum, shstrndx, phnum uint64
	var version uint32
	var ehsize, shentsize, phentsize uint16
	var phsize int
	switch f.class {
	case elf.ELFCLASS32:
		var h elf.Header32
		if err := decode(src, size, 0, f.order, &h); err != nil {
			return nil, err
		}
		shoff, phoff, shnum, shstrndx, phnum = uint64(h.Shoff), uint64(h.Phoff), uint64(h.Shnum), uint64(h.Shstrndx), uint64(h.Phnum)
		version, ehsize, shentsize, phentsize = h.Version, h.Ehsize, h.Shentsize, h.Phentsize
		f.header, f.shentsize, phsize = make([]byte, 52), 40, 32
	case elf.ELFCLASS64:
		var h elf.Header64
		if err := decode(src, size, 0, f.order, &h); err != nil {
			return nil, err
		}
		shoff, phoff, shnum, shstrndx, phnum = h.Shoff, h.Phoff, uint64(h.Shnum), uint64(h.Shstrndx), uint64(h.Phnum)
		version, ehsize, shentsize, phentsize = h.Version, h.Ehsize, h.Shentsize, h.Phentsize
		f.header, f.shentsize, phsize = make([]byte, 64), 64, 56
	default:
		return nil, fmt.Errorf("read ELF: unsupported class")
	}
	if version != uint32(elf.EV_CURRENT) || int(ehsize) != len(f.header) {
		return nil, fmt.Errorf("read ELF: invalid header version or size")
	}
	if _, err := src.ReadAt(f.header, 0); err != nil {
		return nil, fmt.Errorf("read ELF header: %w", err)
	}
	if shoff == 0 {
		if shnum != 0 || shstrndx != 0 || phnum == 0xffff {
			return nil, fmt.Errorf("read ELF: section counts without a section table")
		}
		f.shstrndx = 1
		f.sections = []elf.Section64{{}, {Name: 1, Type: uint32(elf.SHT_STRTAB), Addralign: 1}}
		f.names = []byte("\x00.shstrtab\x00")
	} else {
		if shoff < uint64(len(f.header)) || int(shentsize) != f.shentsize {
			return nil, fmt.Errorf("read ELF: invalid section table offset or entry size")
		}
		zero, err := f.readSection(src, size, shoff)
		if err != nil {
			return nil, err
		}
		if zero.Type != uint32(elf.SHT_NULL) {
			return nil, fmt.Errorf("read ELF: section zero must be SHT_NULL")
		}
		if shnum == 0 {
			shnum = zero.Size
		}
		if shstrndx == uint64(elf.SHN_XINDEX) {
			shstrndx = uint64(zero.Link)
		}
		if phnum == 0xffff {
			phnum = uint64(zero.Info)
		}
		if shnum == 0 || !within(shoff, uint64(f.shentsize), uint64(size)) || shnum > (uint64(size)-shoff)/uint64(f.shentsize) || shnum > uint64(math.MaxInt)/64 {
			return nil, fmt.Errorf("read ELF: section count exceeds file or address space")
		}
		if shstrndx == 0 || shstrndx >= shnum {
			return nil, fmt.Errorf("read ELF: missing or invalid section-name table")
		}
		f.shstrndx = int(shstrndx)
		f.sections = make([]elf.Section64, int(shnum))
		for i := range f.sections {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			s, err := f.readSection(src, size, shoff+uint64(i)*uint64(f.shentsize))
			if err != nil {
				return nil, err
			}
			if i != 0 && s.Type != uint32(elf.SHT_NOBITS) && s.Type != uint32(elf.SHT_NULL) && !within(s.Off, s.Size, uint64(size)) {
				return nil, fmt.Errorf("read ELF: section %d outside file", i)
			}
			f.sections[i] = s
		}
		str := f.sections[f.shstrndx]
		if str.Type != uint32(elf.SHT_STRTAB) || str.Size == 0 || str.Size > math.MaxUint32 || str.Size > uint64(math.MaxInt) {
			return nil, fmt.Errorf("read ELF: invalid section-name table")
		}
		f.names = make([]byte, int(str.Size))
		if _, err := src.ReadAt(f.names, int64(str.Off)); err != nil {
			return nil, fmt.Errorf("read section names: %w", err)
		}
		if f.names[0] != 0 || f.names[len(f.names)-1] != 0 {
			return nil, fmt.Errorf("read ELF: section names must start and end with NUL")
		}
		for i, s := range f.sections {
			if i != 0 && uint64(s.Name) >= uint64(len(f.names)) {
				return nil, fmt.Errorf("read ELF: section %d name outside table", i)
			}
		}
	}
	if phnum == 0 {
		return f, nil
	}
	if phoff < uint64(len(f.header)) || int(phentsize) != phsize || phoff > uint64(size) || phnum > (uint64(size)-phoff)/uint64(phsize) {
		return nil, fmt.Errorf("read ELF: invalid program header table")
	}
	for i := uint64(0); i < phnum; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		offset := phoff + i*uint64(phsize)
		var segment span
		if f.class == elf.ELFCLASS32 {
			var p elf.Prog32
			if err := decode(src, size, offset, f.order, &p); err != nil {
				return nil, err
			}
			segment = span{uint64(p.Off), uint64(p.Filesz)}
		} else {
			var p elf.Prog64
			if err := decode(src, size, offset, f.order, &p); err != nil {
				return nil, err
			}
			segment = span{p.Off, p.Filesz}
		}
		if !within(segment.offset, segment.size, uint64(size)) {
			return nil, fmt.Errorf("read ELF: segment %d outside file", i)
		}
		if segment.size != 0 {
			f.segments = append(f.segments, segment)
		}
	}
	return f, nil
}

func (f *file) readSection(src io.ReaderAt, size int64, offset uint64) (elf.Section64, error) {
	if f.class == elf.ELFCLASS64 {
		var s elf.Section64
		err := decode(src, size, offset, f.order, &s)
		return s, err
	}
	var s elf.Section32
	if err := decode(src, size, offset, f.order, &s); err != nil {
		return elf.Section64{}, err
	}
	return elf.Section64{Name: s.Name, Type: s.Type, Flags: uint64(s.Flags), Addr: uint64(s.Addr), Off: uint64(s.Off), Size: uint64(s.Size), Link: s.Link, Info: s.Info, Addralign: uint64(s.Addralign), Entsize: uint64(s.Entsize)}, nil
}

func (f *file) movable(s elf.Section64) error {
	if s.Type == uint32(elf.SHT_NULL) || s.Type == uint32(elf.SHT_NOBITS) {
		return fmt.Errorf("section has no file data")
	}
	if s.Flags&uint64(elf.SHF_ALLOC) != 0 {
		return fmt.Errorf("allocated section cannot be moved")
	}
	for _, p := range f.segments {
		if s.Size != 0 && s.Off < p.offset+p.size && p.offset < s.Off+s.Size {
			return fmt.Errorf("section overlaps a program segment")
		}
	}
	return nil
}

func (f *file) encodeTable(shoff uint64) ([]byte, error) {
	count, namesIndex := uint64(len(f.sections)), uint64(f.shstrndx)
	f.sections[0].Size, f.sections[0].Link = 0, 0
	if count >= uint64(elf.SHN_LORESERVE) {
		f.sections[0].Size, count = count, 0
	}
	if namesIndex >= uint64(elf.SHN_LORESERVE) {
		if namesIndex > math.MaxUint32 {
			return nil, fmt.Errorf("encode section names: index exceeds 32 bits")
		}
		f.sections[0].Link, namesIndex = uint32(namesIndex), uint64(elf.SHN_XINDEX)
	}
	var table bytes.Buffer
	for _, s := range f.sections {
		if f.class == elf.ELFCLASS32 {
			if s.Flags > math.MaxUint32 || s.Off > math.MaxUint32 || s.Size > math.MaxUint32 || s.Addralign > math.MaxUint32 {
				return nil, fmt.Errorf("encode section: ELF32 field overflow")
			}
			section := elf.Section32{Name: s.Name, Type: s.Type, Flags: uint32(s.Flags), Addr: uint32(s.Addr), Off: uint32(s.Off), Size: uint32(s.Size), Link: s.Link, Info: s.Info, Addralign: uint32(s.Addralign), Entsize: uint32(s.Entsize)}
			if err := binary.Write(&table, f.order, section); err != nil {
				return nil, fmt.Errorf("encode ELF32 section: %w", err)
			}
		} else {
			if err := binary.Write(&table, f.order, s); err != nil {
				return nil, fmt.Errorf("encode ELF64 section: %w", err)
			}
		}
	}
	if f.class == elf.ELFCLASS32 {
		f.order.PutUint32(f.header[32:36], uint32(shoff))
		f.order.PutUint16(f.header[46:48], uint16(f.shentsize))
		f.order.PutUint16(f.header[48:50], uint16(count))
		f.order.PutUint16(f.header[50:52], uint16(namesIndex))
	} else {
		f.order.PutUint64(f.header[40:48], shoff)
		f.order.PutUint16(f.header[58:60], uint16(f.shentsize))
		f.order.PutUint16(f.header[60:62], uint16(count))
		f.order.PutUint16(f.header[62:64], uint16(namesIndex))
	}
	return table.Bytes(), nil
}

func (f *file) wordSize() int {
	if f.class == elf.ELFCLASS32 {
		return 4
	}
	return 8
}

func decode(src io.ReaderAt, size int64, offset uint64, order binary.ByteOrder, value any) error {
	n := binary.Size(value)
	if n < 0 || !within(offset, uint64(n), uint64(size)) {
		return fmt.Errorf("read ELF structure: out of bounds")
	}
	if err := binary.Read(io.NewSectionReader(src, int64(offset), int64(n)), order, value); err != nil {
		return fmt.Errorf("read ELF structure: %w", err)
	}
	return nil
}

func within(offset, size, limit uint64) bool { return offset <= limit && size <= limit-offset }

func place(end, size, alignment, limit uint64) (uint64, uint64, error) {
	padding := (alignment - end%alignment) % alignment
	if end > limit || padding > limit-end || size > limit-end-padding {
		return 0, 0, fmt.Errorf("edit ELF: output exceeds file offset limit")
	}
	offset := end + padding
	return offset, offset + size, nil
}

func copyBytes(ctx context.Context, dst io.Writer, src io.Reader, size int64) error {
	buf := make([]byte, 64*1024)
	for size > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(src, buf[:min(size, int64(len(buf)))])
		if err != nil {
			return err
		}
		if err := writeAll(dst, buf[:n]); err != nil {
			return err
		}
		size -= int64(n)
	}
	return nil
}

func writeZeros(ctx context.Context, dst io.Writer, size uint64) error {
	var buf [4096]byte
	for size > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(size, uint64(len(buf)))
		if err := writeAll(dst, buf[:n]); err != nil {
			return fmt.Errorf("write padding: %w", err)
		}
		size -= n
	}
	return nil
}

func writeAll(dst io.Writer, data []byte) error {
	n, err := dst.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
