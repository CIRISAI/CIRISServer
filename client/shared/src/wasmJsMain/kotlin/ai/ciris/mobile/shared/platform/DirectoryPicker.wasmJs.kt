package ai.ciris.mobile.shared.platform

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect

// Browsers have no concept of a server-side directory path; the holder types it.
// No-op that resets the caller's `show` flag.
//
// NODE VENDOR DRIFT #30 (restored after the 2.9.28 re-vendor dropped it):
// `purpose` is accepted and ignored: these platforms open no chooser, so there is
// no title or start directory to vary. It stays in the signature so the day one
// of them DOES open a chooser, the caller's intent is already there to honour
// rather than something to go back and thread through.
@Composable
actual fun DirectoryPickerDialog(
    show: Boolean,
    purpose: DirectoryPickerPurpose,
    onDirectoryPicked: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    LaunchedEffect(show) {
        if (show) onDismiss()
    }
}
