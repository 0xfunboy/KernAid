# Linux hardware inventory v1

KernAid Resident and KernAid Rescue call the same
`kernaid-linux-hardware-inventory` implementation. The production entrypoint
accepts no arguments and reads only fixed sources belonging to the running
machine:

- `/proc/cpuinfo` for logical CPU count, normalized vendor/model values and the
  presence of VMX/SVM hardware virtualization flags;
- `/proc/meminfo` for `MemTotal` converted to bytes;
- `/sys/firmware/efi` for the observed boot mode;
- six public `/sys/class/dmi/id` model/vendor fields;
- `/sys/bus/pci/devices` for class, vendor and device IDs;
- `/sys/bus/usb/devices` for class, vendor and product IDs.

Every file, array and final JSON document has a fixed byte or entry limit. The
device arrays are sorted and deduplicated, so kernel enumeration order does not
change the document. Source failures use the closed states `complete`,
`partial`, `truncated`, `unavailable` and `invalid`; error text and source bytes
are never substituted into the normalized document.

Resident runs at most one hardware collector worker and waits five seconds. A
timeout poisons that process-local collector slot permanently, so a kernel read
that never returns cannot freeze the UI or multiply blocked threads; restarting
Desk discards the process and its slot. Rescue uses the same collector in a
one-shot process with a bounded process-group timeout.

The contract deliberately excludes serial numbers, machine UUIDs, asset tags,
network identifiers, filesystem paths, PCI bus addresses and USB topology
addresses. DMI strings are whitespace-normalized, control- and
bidirectional-control-free, and capped at 256 UTF-8 bytes. They remain observed,
untrusted system data. The document is bound into the local session and report,
but neither its values nor its evidence reference are copied into the remote
provider context.

The browser validates the exact object shape before creating evidence. The
published JSON contract is
`packages/schemas/linux-hardware-inventory.schema.json`. JSON Schema expresses
the portable shape; both shipping parsers additionally require canonical JSON,
a 256-byte UTF-8 text cap, UTF-8 byte ordering and aggregate device counts no
greater than 256. Linux hardware facts do not participate in the Rescue target
fingerprint: hot-plugging a peripheral cannot silently retarget an
installed-system session, while the existing storage/hostname identity binding
remains unchanged.

QEMU proves the shipping binary is packaged and that core CPU and memory facts
are available in both BIOS and UEFI Rescue boots. SMART/NVMe telemetry belongs
to the separate [Linux storage health contract](linux-storage-health.md), so it
cannot silently expand this general inventory. Neither QEMU contract proves
physical device compatibility, sensor correctness or firmware support; those
remain explicit hardware-lab gates.
