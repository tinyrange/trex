# Minidump contexts and stack sources

`windows.minidump(file)` preserves the architecture-specific bytes of both the
exception stream's `context` and each thread's `context`. These contexts are
independent: a producer may capture them at different points. An absent context
is empty bytes; nonempty descriptors are range-checked and limited to 1 MiB.

The exception record's `address` need not equal the saved context's instruction
pointer. For example, an Explorer taskbar fail-fast dump records a Taskbar.dll
failure address while its exception context points into
`KernelBase!RaiseFailFastException`. Unwind the context instead of substituting
the exception address into its registers.

Thread-list `stack` bytes and full-memory `memory` ranges are likewise separate
dump contents. Do not assume a nonempty thread stack is useful solely because
its descriptor is in bounds. In the inspected Explorer dump, the thread-list
stack was zero-filled while the Memory64 stream contained the actual stack at
the same virtual addresses. Using that memory with the saved context recovered
the fail-fast caller chain back through `TrayUI::StartTaskbar`.

The parser exposes these sources without silently merging or replacing them.
When debugging a partial or inconsistent dump, identify the chosen source and
reject missing ranges rather than synthesizing stack bytes.
