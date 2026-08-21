package ai.ciris.mobile.shared.platform

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.swing.JFileChooser
import javax.swing.SwingUtilities
import javax.swing.filechooser.FileNameExtensionFilter
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
@Composable
actual fun FilePickerDialog(
    show: Boolean,
    mimeTypes: List<String>,
    onFilePicked: (PickedFile) -> Unit,
    onDismiss: () -> Unit
) {
    LaunchedEffect(show) {
        if (!show) return@LaunchedEffect

        // NODE VENDOR DRIFT #18 (restored after the 2.9.28 re-vendor dropped it):
        // the CHOOSER runs on the EDT (Swing's contract — see chooseFileOnEdt);
        // the file READ stays on IO, because a multi-MB attachment must not be
        // read on the event thread. Splitting them is the point: upstream's
        // version ran BOTH on Dispatchers.IO, which is how the sibling directory
        // picker crashed the whole app mid-ceremony (IndexOutOfBoundsException
        // out of DefaultRowSorter, via FilePane.doDirectoryChanged).
        val chosen = chooseFileOnEdt(mimeTypes)
        val result = chosen?.let { withContext(Dispatchers.IO) { readDesktopFile(it) } }

        if (result != null) {
            onFilePicked(result)
        } else {
            onDismiss()
        }
    }
}

/**
 * NODE VENDOR DRIFT #18 (restored after the 2.9.28 re-vendor dropped it).
 *
 * Show the file chooser ON THE EDT and return the selected [File], or `null` on
 * cancel or failure.
 *
 * Swing may only be touched from the Event Dispatch Thread. A picker failure is a
 * cancelled pick, never a crash — attaching a file is a convenience and must not
 * be able to take the app down.
 */
private fun chooseFileOnEdt(mimeTypes: List<String>): File? {
    val picked = arrayOfNulls<File>(1)
    val body = Runnable {
        try {
            picked[0] = showNativeFileChooser(mimeTypes)
        } catch (t: Throwable) {
            PlatformLogger.w(
                "FilePicker",
                "file picker failed (${t::class.simpleName}: ${t.message}) — treating as cancelled",
            )
        }
    }
    return try {
        if (SwingUtilities.isEventDispatchThread()) body.run() else SwingUtilities.invokeAndWait(body)
        picked[0]
    } catch (t: Throwable) {
        PlatformLogger.w("FilePicker", "file picker dispatch failed: ${t.message}")
        null
    }
}

// Returns the chosen FILE: reading it is the caller's job, off the EDT (#18).
private fun showNativeFileChooser(mimeTypes: List<String>): File? {
    val chooser = JFileChooser().apply {
        dialogTitle = "Select file to attach"
        isMultiSelectionEnabled = false

        // Build extension filters from MIME types
        val extensions = mutableListOf<String>()
        for (mime in mimeTypes) {
            when (mime) {
                "image/jpeg" -> extensions.addAll(listOf("jpg", "jpeg"))
                "image/png" -> extensions.add("png")
                "image/gif" -> extensions.add("gif")
                "image/webp" -> extensions.add("webp")
                "application/pdf" -> extensions.add("pdf")
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document" -> extensions.add("docx")
            }
        }

        if (extensions.isNotEmpty()) {
            fileFilter = FileNameExtensionFilter(
                "Supported files (${extensions.joinToString(", ") { "*.$it" }})",
                *extensions.toTypedArray()
            )
        }
    }

    val result = chooser.showOpenDialog(null)
    if (result != JFileChooser.APPROVE_OPTION) return null
    return chooser.selectedFile
}

@OptIn(ExperimentalEncodingApi::class)
private fun readDesktopFile(file: File): PickedFile? {
    return try {
        val sizeBytes = file.length()
        if (sizeBytes > PickedFile.MAX_FILE_SIZE_BYTES) {
            println("[FilePicker] File too large: $sizeBytes bytes")
            return null
        }

        val bytes = file.readBytes()
        val base64 = Base64.encode(bytes)
        val mediaType = guessMimeType(file.name)

        PickedFile(
            name = file.name,
            mediaType = mediaType,
            dataBase64 = base64,
            sizeBytes = sizeBytes
        )
    } catch (e: Exception) {
        println("[FilePicker] Failed to read file: ${e.message}")
        null
    }
}

private fun guessMimeType(fileName: String): String {
    val ext = fileName.substringAfterLast('.', "").lowercase()
    return when (ext) {
        "jpg", "jpeg" -> "image/jpeg"
        "png" -> "image/png"
        "gif" -> "image/gif"
        "webp" -> "image/webp"
        "pdf" -> "application/pdf"
        "docx" -> "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        else -> "application/octet-stream"
    }
}
