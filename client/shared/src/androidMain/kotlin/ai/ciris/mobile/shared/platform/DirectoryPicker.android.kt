package ai.ciris.mobile.shared.platform

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect

// TODO: wire the Storage Access Framework tree picker (ACTION_OPEN_DOCUMENT_TREE)
// for removable media. Until then the holder types the path; this is a no-op that
// simply resets the caller's `show` flag.
//
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
