//! `scoring/` module — N_eff (Kish), capacity band, LC-AV-18
//! assembly gate, and the `ManifoldConformity` result enum.
//! See MISSION.md §2 scoring/.

pub mod assembly;
pub mod axis_calibration;
pub mod calibration;
pub mod capacity;
pub mod n_eff;
pub mod result;

pub use assembly::{assemble, AssemblyInput};
pub use axis_calibration::{
    AxisCalibration, AxisCalibrationError, AxisEntry, CalibrationOutcome, Polarity,
    ThresholdFunction, AXIS_CALIBRATION_VERSION, RATCHET_AXIS_CALIBRATION_VERSION,
};
pub use calibration::{
    BundleError, CalibrationBundle, CohortCentroid, Projection, Standardization,
};
pub use capacity::capacity;
pub use n_eff::kish_n_eff;
pub use result::{
    AxisFamily, DetectionEvent, IndeterminateReason, ManifoldConformity, Score, Severity,
    UnavailableReason,
};
