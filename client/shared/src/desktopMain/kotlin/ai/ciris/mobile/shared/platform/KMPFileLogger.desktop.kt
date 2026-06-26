package ai.ciris.mobile.shared.platform

import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

actual fun appendToFile(path: String, text: String) {
    File(path).appendText(text)
}

actual fun getFileSize(path: String): Long {
    val f = File(path)
    return if (f.exists()) f.length() else 0L
}

actual fun deleteFile(path: String) {
    File(path).delete()
}

actual fun renameFile(from: String, to: String) {
    File(from).renameTo(File(to))
}

actual fun ensureDirectoryExists(path: String) {
    File(path).mkdirs()
}

actual fun getCurrentTimestamp(): String {
    return SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
}

actual fun getKMPLogDir(): String {
    // Mirror CIRISAgent's path convention (path_resolution.py): honor CIRIS_HOME
    // when set, else fall back to ~/ciris. Logs land in <home>/ciris/logs.
    val cirisHome = System.getenv("CIRIS_HOME")?.takeIf { it.isNotBlank() }
    if (cirisHome != null) return "$cirisHome/logs"
    val home = System.getProperty("user.home") ?: "/tmp"
    return "$home/ciris/logs"
}
