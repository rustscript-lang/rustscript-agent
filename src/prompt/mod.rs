//! Frozen minimal coding system prompt.
//!
//! Prompt text is rendered from explicit [`BuildInputs`]. Pure rendering never
//! reads the wall clock, the environment, or the filesystem. Date, platform,
//! architecture, and the admitted tool snapshot are captured once at run
//! admission and stored on the run handle and run context so later file,
//! schema, or date changes cannot drift the same run.
//!
//! Untrusted project guidance uses a deterministic length-prefixed JSON
//! representation (`untrusted-file bytes=<N>` plus exactly `N` bytes of
//! `{"body":...,"name":...}`). File contents are JSON-string escaped inside
//! the counted payload and must not be interpreted as instructions.

mod coding;

pub use coding::{
    BuildInputs, CodingPromptBudgets, DateSource, FixedDateSource, GUIDANCE_FILE_NAMES,
    LoadedGuidance, PromptBuildError, SystemDateSource, TRUNCATION_MARKER, UNTRUSTED_FILE_HEADER,
    build_coding_prompt, render_coding_prompt,
};
