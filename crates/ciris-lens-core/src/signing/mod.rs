//! `signing/` module — canonicalize + local_sign for detection events.
//! See MISSION.md §2 signing/.

pub mod event;

pub use event::{
    assemble_event, prepare_detection, sign_detection, DetectionInputs, PreparedDetection,
    SigningError,
};
