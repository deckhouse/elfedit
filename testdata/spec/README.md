# Specification fixtures

Default tests use checked-in bytes or deterministic builders; clang, objcopy and
readelf are not runtime/unit-test dependencies. Encoding coverage is not evidence
of execution on the named architectures.

## Compiler-generated object

`sections.elf` is an ELF64 little-endian x86-64 relocatable object generated from
`sections.s`. It contains mergeable strings, a symbol table and a COMDAT note.
The `.strtab` selected for section names also supplies symbol names. Regenerate
from the repository root:

```sh
clang -target x86_64-linux-gnu -c testdata/spec/sections.s -o testdata/spec/sections.elf
readelf -hSWgs testdata/spec/sections.elf
```

Provenance: Apple clang 21.0.0 (`clang-2100.1.1.101`). Another compiler version may
change ordering/bytes; regenerate deliberately and rerun the structural tests.
`TestSpecificationObject` checks actual symbols, group references, member flags,
merge entry size, active metadata and payloads, not just parser/tool exit status.

## Coverage map

References: [gABI sections](https://gabi.xinuos.com/elf/03-sheader.html),
[string tables](https://gabi.xinuos.com/elf/04-strtab.html),
[ELF header](https://gabi.xinuos.com/elf/02-eheader.html),
[program headers](https://gabi.xinuos.com/elf/07-pheader.html),
[relocations](https://gabi.xinuos.com/elf/06-reloc.html).
`PN_XNUM` additionally follows the extended `e_phnum`/section-zero `sh_info`
convention documented in [elf(5)](https://man7.org/linux/man-pages/man5/elf.5.html).

| Case / clause | Fixture and tests | Expected behavior |
| --- | --- | --- |
| ELF32/64 × LE/BE; header §2.2 | Existing `encodings`/`fixture`; new `metadataFixture` | Preserve identity/byte order. Builders use standard-library ABI structures, not production writer output. |
| Shared, suffix and index-selected strings; §4 | Existing `sharedNamesFixture`, `TestPreserveSectionNameTable`, `TestExactAndSuffixNames`, `TestPreserveNameTableOptIn` | Retain numeric offsets/symbol references; use selected index rather than label; exact target matching. |
| Empty selected table; §4 | Existing `TestEmptySectionNames` | Accept zero indexes, preserve original zero-size header when detaching; reject nonzero names. |
| Inactive sections/segments; §§3.3, 7.2 | Existing `TestInactiveSections`, `TestUnusedProgramHeaders`, `TestUnusedProgramTableProtection` | Ignore undefined inactive geometry, retain bytes; protect physical program table and active ranges. |
| COMDAT relationships; §3.9 | `sections.elf`, `metadataFixture`, `TestExplicitGroupFlagsAndStagedMember` | Editor uses caller flags exactly, in-place and append. Staged member addition followed by existing group-payload replacement remains allowed. Final list/flags/Link/Info/Entsize are checked. |
| Required metadata; §§3.2–3.5, relocation §6.2 | `TestCreationRequiresDependentMetadata` | Both APIs reject new MERGE/STRINGS and SYMTAB/DYNSYM/REL/RELA/HASH/DYNAMIC/GROUP/SYMTAB_SHNDX/RELR requests with exact dependent-field errors and nil/empty output. |
| Existing structured/merge sections; §§3.2–3.5 | `metadataFixture`, `TestDependentMetadataReplacement`, `TestSpecificationObject` | Both APIs preserve Link/Info/Entsize and valid symbols across in-place/append replacement. |
| Opaque application/vendor sections; §3.3 | `TestCreationAllowsOpaqueMetadata` | PROGBITS, NOTE, STRTAB and representative OS/processor/application types remain addable. No type whitelist. |
| Zero-size/NOBITS/alignment; §§3.2–3.3 | Existing `fixture`, `TestSetSection`, `TestReplaceInPlace`, `TestAppendedReplacementMetadata` | Preserve conceptual NOBITS placement; use requested alignment and retain active metadata. |
| Extended section count/name index; §§2, 3.1 | Existing `TestExtendedNumbering`, `TestPreserveNameTableBoundaries` | Generate threshold-scale inputs on demand; retain indexes across SHN_LORESERVE. |
| Extended program count | `TestExtendedProgramCount`, counts 65535 and 65536 | Generate real-size tables on demand; preserve escape/count fields and inspect final resolved entry. Small noncanonical escaped counts are not valid-input fixtures. |
| Opaque compression; §3.7 | Existing `TestCompressedPayload` | Preserve raw header/stream; decompressed payload independently checked. |
| Unsupported selected tables; §§3.7, 4 | `TestUnsupportedNameTableFixtures` | Valid compressed-name-table encoding and absent selected table are rejected by exact documented errors, before output, with input unchanged. |

Creation errors name the missing fields and `SectionOptions`. Function-pointer
array types are deliberately not added to the rejection set merely because they
contain arrays: ordinary clang relocatable INIT_ARRAY/FINI_ARRAY sections use
zero `sh_entsize`. No general payload, linker or cross-section consistency
validator is claimed. Mapped/allocated editing remains outside the documented
scope; this corpus does not expand that support.
