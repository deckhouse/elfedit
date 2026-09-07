# elfedit

A small pure-Go ELF section writer. Standard library only; no CGo, subprocesses or architecture-specific backends at runtime.

`SetSection` adds or replaces a named **non-allocated** section with caller-provided bytes, type, flags and alignment. `WriteSection` performs the same operation from an `io.ReaderAt` into a separate `io.Writer`, without loading the entire input file into memory.

Requires Go 1.25 or newer.

```sh
go get github.com/deckhouse/elfedit
```

```go
import (
    "debug/elf"

    "github.com/deckhouse/elfedit"
)
```

```go
output, err := elfedit.SetSection(ctx, input, ".metadata", payload, elfedit.SectionOptions{
    Type:      elf.SHT_PROGBITS,
    Alignment: 8,
})
```

For large files, open distinct source and destination files, then call:

```go
err := elfedit.WriteSection(ctx, dst, src, sourceSize, ".note.example", noteBytes, elfedit.SectionOptions{
    Type:      elf.SHT_NOTE,
    Alignment: 4,
})
```

The caller builds the note envelope in the target ELF byte order. The writer treats section contents as opaque bytes. Hashing, signature bundles, key access, certificate policy and verification belong to consumers such as `delivery-kit-sdk`, not this module.

## Scope

- ELF32 and ELF64, little- and big-endian. `e_machine`, ABI identity and machine flags are preserved without a machine allowlist.
- Adding a section appends its data, an extended copy of the section-name table, and a new section-header table. Existing section indexes and name offsets remain stable.
- Replacing a section keeps its index, `sh_link`, `sh_info`, `sh_addr` and `sh_entsize`. Type, flags, alignment, offset and size are supplied by the operation. The name table is not rewritten.
- Extended section counts and string-table indexes use the `SHN_LORESERVE` boundary; extended program counts are read from section zero and preserved.
- Files without a section table receive a new one. Files with an existing table but no section-name table are currently rejected.
- Program headers and existing section data, gaps and overlays are retained byte for byte. Only section-table fields of the ELF header change. Old tables and old payload bytes remain in the file; repeated replacements grow it. This is not secure erasure.

This covers the add/update/flags subset of `objcopy` needed to store metadata, not the complete `objcopy` command line. For a signature section, one replacement substitutes for `--remove-section` followed by `--add-section`, without changing other section indexes. There is no deletion, stripping, relocation, allocated-section editing, archive support or binary-format conversion. Output layout is not byte-identical to GNU objcopy's layout.

Allocated sections, sections overlapping a program segment, direct replacement of the section-name table, duplicate target names, invalid ranges and arithmetic overflow are rejected. Moving mapped data requires adjusting loader semantics and is intentionally outside this API.

`WriteSection` requires a stable source and a distinct destination. Validation precedes output, but I/O failures or cancellation can leave partial output: write a temporary file and finalize it only on success. File permissions and atomic replacement belong to the caller. There is no 512 MiB artifact limit; metadata, names and the new payload still occupy memory.

The reader validates the structures this operation uses, not every machine-specific relocation or ABI rule. Supporting all `e_machine` values does not mean every architecture has been executed in tests.

## Validation

```sh
task format
task build
task lint
task test -- -race
task fuzz
task test:binutils
task test:linux
```

Unit tests cover ELF32/64 × both byte orders, known and unknown machines, replacement, byte preservation, extended numbering, malformed inputs, streaming a synthetic 600 MiB file, and ELF32 overflow. Output is inspected with Go's independent `debug/elf` reader.

`test:binutils` requires clang and GNU `objcopy`/`readelf` in PATH. It compiles actual ELF object files for i386, x86_64, ARM LE/BE and AArch64 LE/BE; checks notes with readelf, extracts payloads with objcopy, and updates sections created by objcopy. On macOS, GNU tools can be placed in PATH with `PATH="$(brew --prefix binutils)/bin:$PATH"`.

`test:linux` runs an edited `/bin/true` in a disposable local Go container with networking disabled and source mounted read-only. Docker must have `golang:1.25.5-bookworm` available.

Format references: [ELF header](https://gabi.xinuos.com/elf/02-eheader.html), [sections](https://gabi.xinuos.com/elf/03-sheader.html), [GNU objcopy](https://sourceware.org/binutils/docs/binutils/objcopy.html).
