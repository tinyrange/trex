- Implement archive, filesystem, binary-format, and debugging protocol support
  in Go using trex file, byte-channel, event, and clock abstractions.
- Repository code and committed scripts must not delegate supported
  functionality to host parsing, mounting, extraction, conversion, debugger,
  or image-building tools.
- Production-code exceptions for launching external processes are QEMU acting
  as the emulator/debugging target and FFmpeg solely for encoding QEMU video
  recordings. Stream frames and encoded output through pipes/in-memory
  abstractions, never intermediate host files. This does not authorize arbitrary
  FFmpeg commands or other host conversion tools. QEMU or guest software must
  not substitute for missing image construction, parsing, or conversion logic.
- Do not extract inputs or create host files to transfer intermediate data
  between processing stages. Explicit final outputs requested by the user,
  including complete disk images, screenshots, traces, and reports, are
  allowed.
- A final output must be useful independently of the processing pipeline. Do
  not relabel intermediate data as a final output or debugging artifact.
- Keep stable APIs independent of operating-system paths, processes, and
  sockets so the core can be ported to browsers and other constrained
  environments. Native details belong behind backend interfaces.
- These are completion requirements, not preferences. Implementation
  difficulty, a missing library, or the availability of an easier host tool
  does not permit a wrapper, reduced scope, external fallback, or
  filesystem-based workaround. Implement and verify missing capabilities
  directly.
