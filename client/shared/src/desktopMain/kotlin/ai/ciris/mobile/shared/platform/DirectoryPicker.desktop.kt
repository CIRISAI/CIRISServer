package ai.ciris.mobile.shared.platform

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
    onDirectoryPicked: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    LaunchedEffect(show) {
        if (!show) return@LaunchedEffect
        // Dispatchers.IO only to get OFF the Compose frame thread; `chooseDirectory`
        // hops to the EDT itself. Swing must never be touched from an IO thread.
        val path = withContext(Dispatchers.IO) { chooseDirectory() }
        if (path != null) onDirectoryPicked(path) else onDismiss()
    }
}

/**
 * Show the USB folder picker and return the chosen absolute path, or `null` if the
 * holder cancelled — or if the picker failed for any reason.
 *
 * ## Why this runs on the EDT, and why that is not optional
 *
 * Swing components may only be touched from the Event Dispatch Thread. This ran
 * entirely inside `withContext(Dispatchers.IO)`, and `setCurrentDirectory` on an
 * already-constructed chooser fires a `PropertyChangeEvent` straight into a live
 * `FilePane`, which re-sorts and re-lays-out its list. Off the EDT that races its
 * own `DefaultRowSorter` and throws:
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
 */
private fun chooseDirectory(): String? {
    // Start at a removable-media mount root when one exists, so the holder lands
    // near their USB key instead of $HOME. Resolved BEFORE touching Swing.
    val user = System.getProperty("user.name") ?: ""
    val start: File? =
        listOf("/media/$user", "/run/media/$user", "/media", "/Volumes")
            .map(::File)
            .firstOrNull { it.isDirectory && it.canRead() }

    val picked = arrayOfNulls<String>(1)

    val body = Runnable {
        try {
            // Directory via the constructor — see (2) above.
            val chooser =
                JFileChooser(start).apply {
                    dialogTitle = "Select the mounted USB folder"
                    fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
                    isMultiSelectionEnabled = false
                }
            if (chooser.showDialog(null, "Select") == JFileChooser.APPROVE_OPTION) {
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
