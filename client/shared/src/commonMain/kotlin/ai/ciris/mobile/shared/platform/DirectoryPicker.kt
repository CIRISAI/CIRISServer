package ai.ciris.mobile.shared.platform

import androidx.compose.runtime.Composable

/**
 * NODE VENDOR DRIFT #30 (restored after the 2.9.28 re-vendor dropped it): WHY a
 * folder is being chosen — the question the picker is actually asking.
 *
 * This picker was written for ONE job (find the holder's mounted USB) and its
 * title and start directory were baked in to suit it. Then callers with a
 * different job reused it, because it was the only folder picker there was — and
 * "save the genesis seed" opened a dialog titled *Select the mounted USB folder*
 * rooted at `/media`. The operator had just finished a hardware ceremony, so a
 * USB prompt looked plausible enough to obey; the seed went somewhere nobody
 * meant it to go.
 *
 * That is one component answering two questions, which is this codebase's most
 * expensive recurring shape. The cure is not a second picker — two
 * implementations of "choose a folder" would drift the way any two copies do —
 * it is making the question an ARGUMENT, so a caller cannot fail to state which
 * one it is asking.
 */
enum class DirectoryPickerPurpose {
    /**
     * Removable media: the holder's AEAD-wrapped ML-DSA-65 half, a portable
     * identity, a node-list backup. Starts at a mount root, and says so.
     */
    UsbCustody,

    /**
     * An ordinary "where should this file go" — the genesis seed, a co-scrub
     * partial. Starts wherever the operator lives, because the answer is usually
     * their home or Documents, and a USB is merely one possibility among many.
     */
    SaveFile,
}

/**
 * Native **folder** picker — returns the selected directory's absolute PATH (not
 * its contents, unlike [FilePickerDialog]).
 *
 * Render it (like [FilePickerDialog]) and flip [show] to `true` to open the native
 * chooser; it calls [onDirectoryPicked] with the absolute path on confirm, or
 * [onDismiss] on cancel. The caller resets [show] in both callbacks.
 *
 * ## What a folder is being chosen FOR
 *
 * NODE VENDOR DRIFT #20 / #30: removable media, mostly — the accord holder's
 * AEAD-wrapped ML-DSA-65 half, a portable identity, a node-list backup, the
 * things that live on a USB key precisely because they must be able to leave the
 * machine. But callers with a different question ("where should this genesis seed
 * be saved?") reuse this picker too, because it is the only folder picker there
 * is. Our version makes that question an ARGUMENT — [purpose], required, with no
 * default — because one component silently answering two questions is this
 * codebase's most expensive recurring shape, and here it cost an operator their
 * seed's location. [purpose] decides the dialog title and where it opens; see
 * [DirectoryPickerPurpose] for why it is required rather than defaulted.
 *
 * ## Threading contract for actuals
 *
 * An actual that opens a real native chooser must open it on that toolkit's UI
 * thread — see the desktop actual (NODE VENDOR DRIFT #13), where running
 * `JFileChooser` off the Swing EDT crashed a node mid-ceremony out of
 * `FilePane.doDirectoryChanged`. A picker failure is a CANCELLED PICK, never a
 * crash: choosing a folder is a convenience, and the holder can always type the
 * path instead.
 *
 * - Desktop: `JFileChooser` in DIRECTORIES_ONLY mode, on the EDT (the ceremony path).
 * - Android/iOS/wasm: no-op for now (the text field stays the source of truth) —
 *   TODO wire the SAF tree picker / iOS document picker for removable media.
 */
@Composable
expect fun DirectoryPickerDialog(
    show: Boolean,
    purpose: DirectoryPickerPurpose,
    onDirectoryPicked: (String) -> Unit,
    onDismiss: () -> Unit,
)
