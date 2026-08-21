package ai.ciris.mobile.shared.platform

import ai.ciris.mobile.shared.localization.localizedString
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import java.io.File
import javax.swing.JFileChooser
import javax.swing.SwingUtilities
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
actual fun DirectoryPickerDialog(
    show: Boolean,
    purpose: DirectoryPickerPurpose,
    onDirectoryPicked: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    // NODE VENDOR DRIFT #30 (cont.): the dialog title is the picker's ONLY
    // user-visible string, and it was hardcoded English in all 29 languages.
    // It is resolved HERE, at the composable level, because `localizedString`
    // reads a CompositionLocal — `chooseDirectory` runs on a background
    // dispatcher and then the Swing EDT, where no composition exists — so the
    // resolved String is handed DOWN rather than the key being looked up from
    // outside the composition.
    val (titleKey, englishTitle) =
        when (purpose) {
            DirectoryPickerPurpose.UsbCustody ->
                "mobile.directory_picker_usb_title" to "Select the mounted USB folder"
            DirectoryPickerPurpose.SaveFile ->
                "mobile.directory_picker_save_title" to "Choose where to save the file"
        }
    // `localizedString` returns the KEY itself when the bundle has no entry yet
    // (or is still loading). A folder chooser headed
    // `mobile.directory_picker_usb_title` is worse than an untranslated one, so
    // an unresolved key falls back to the English text this replaced.
    val resolvedTitle = localizedString(titleKey)
    val title = if (resolvedTitle == titleKey) englishTitle else resolvedTitle
    // The APPROVE BUTTON is the picker's second user-visible string and was
    // missed the first time round because the title got all the attention. Same
    // treatment, same fallback.
    val resolvedApprove = localizedString("mobile.directory_picker_approve")
    val approveLabel =
        if (resolvedApprove == "mobile.directory_picker_approve") "Select" else resolvedApprove

    // Keyed on `show` alone, NOT on `title`: a language change while the native
    // chooser is already open must not relaunch it. The title is captured as the
    // dialog opens.
    LaunchedEffect(show) {
        if (!show) return@LaunchedEffect
        // NODE VENDOR DRIFT #13: Dispatchers.IO only to get OFF the Compose frame
        // thread; `chooseDirectory` hops to the EDT itself. Swing must never be
        // touched from an IO thread.
        val path = withContext(Dispatchers.IO) { chooseDirectory(purpose, title, approveLabel) }
        if (path != null) onDirectoryPicked(path) else onDismiss()
    }
}

/**
 * NODE VENDOR DRIFT #13 (restored after the 2.9.28 re-vendor dropped it).
 *
 * Show the folder picker and return the chosen absolute path, or `null` if the
 * operator cancelled — or if the picker failed for any reason.
 *
 * ## Why this runs on the EDT, and why that is not optional
 *
 * Swing components may only be touched from the Event Dispatch Thread. Upstream's
 * version ran entirely inside `withContext(Dispatchers.IO)`, and
 * `setCurrentDirectory` on an already-constructed chooser fires a
 * `PropertyChangeEvent` straight into a live `FilePane`, which re-sorts and
 * re-lays-out its list. Off the EDT that races its own `DefaultRowSorter` and
 * throws:
 *
 * ```
 * java.lang.IndexOutOfBoundsException: Invalid index
 *   at javax.swing.DefaultRowSorter.convertUnsortedUnfiltered
 *   at sun.swing.FilePane$SortableListModel.getElementAt
 *   at sun.swing.FilePane.doDirectoryChanged
 *   at javax.swing.JFileChooser.setCurrentDirectory
 *   at DirectoryPicker.desktop.kt:34
 * ```
 *
 * That crash reached a holder mid-ceremony, with the YubiKeys out, and took the
 * whole node down with it.
 *
 * Three separate fixes, because one would have left the others latent:
 *
 * 1. **Everything happens on the EDT** (`invokeAndWait`). The Swing contract.
 * 2. **The start directory is a CONSTRUCTOR argument.** `JFileChooser(File)` sets
 *    it before any UI exists, so no property change is delivered to a live
 *    `FilePane` at all. Even on the EDT, mutating it afterwards is the more
 *    fragile of the two spellings.
 * 3. **A picker failure is a CANCELLED PICK, never a crash.** Choosing a folder is
 *    a convenience; a look-and-feel quirk on some desktop must not be able to
 *    terminate a node that is holding an in-progress hardware ceremony. The holder
 *    can still type the path.
 *
 * NODE VENDOR DRIFT #30 (restored after the 2.9.28 re-vendor dropped it): the
 * title and start directory follow [purpose], and used to follow neither — both
 * were hardcoded for USB custody, so "save the genesis seed" opened a dialog
 * headed *Select the mounted USB folder* rooted at /media. See
 * [DirectoryPickerPurpose] for what that cost.
 *
 * [title] arrives already localized and already chosen for [purpose] — see
 * [DirectoryPickerDialog], which resolves it while it still has a composition to
 * read the localization CompositionLocal from. [purpose] still decides the START
 * DIRECTORY here, which is a filesystem question and not a translatable one.
 */
private fun chooseDirectory(
    purpose: DirectoryPickerPurpose,
    title: String,
    approveLabel: String,
): String? {
    // Resolved BEFORE touching Swing — see (2) above.
    val user = System.getProperty("user.name") ?: ""
    val removable: File? =
        listOf("/media/$user", "/run/media/$user", "/media", "/Volumes")
            .map(::File)
            .firstOrNull { it.isDirectory && it.canRead() }
    val home: File? = System.getProperty("user.home")?.let(::File)?.takeIf { it.isDirectory }

    // NODE VENDOR DRIFT #30 (restored after the 2.9.28 re-vendor dropped it):
    // the question the dialog asks is the CALLER's, not this file's. The TITLE
    // half now arrives localized from the composable; this is the WHERE half.
    val start: File? =
        when (purpose) {
            // Land near the USB key rather than $HOME; fall back to home when no
            // removable mount exists, because an empty chooser helps nobody.
            DirectoryPickerPurpose.UsbCustody -> removable ?: home
            // The answer is usually home or Documents. A USB is reachable from
            // there like any other folder; the reverse is not true, which is why
            // the wrong default cost an operator their seed's location.
            DirectoryPickerPurpose.SaveFile -> home
        }

    val picked = arrayOfNulls<String>(1)

    val body = Runnable {
        try {
            // Directory via the constructor — see (2) above.
            val chooser =
                JFileChooser(start).apply {
                    dialogTitle = title
                    fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
                    isMultiSelectionEnabled = false
                }
            if (chooser.showDialog(null, approveLabel) == JFileChooser.APPROVE_OPTION) {
                picked[0] = chooser.selectedFile?.absolutePath
            }
        } catch (t: Throwable) {
            // See (3). Swallow deliberately and report a cancel.
            PlatformLogger.w(
                "DirectoryPicker",
                "folder picker failed (${t::class.simpleName}: ${t.message}) — treating as " +
                    "cancelled. Type the USB path directly; the ceremony is unaffected.",
            )
        }
    }

    return try {
        if (SwingUtilities.isEventDispatchThread()) {
            body.run()
        } else {
            SwingUtilities.invokeAndWait(body)
        }
        picked[0]
    } catch (t: Throwable) {
        PlatformLogger.w("DirectoryPicker", "folder picker dispatch failed: ${t.message}")
        null
    }
}
