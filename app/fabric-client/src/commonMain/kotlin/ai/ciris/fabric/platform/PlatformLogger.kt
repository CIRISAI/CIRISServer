package ai.ciris.fabric.platform

/**
 * Minimal multiplatform logger. Copied (slimmed) from the CIRISAgent KMP
 * client's PlatformLogger so the copied federation surfaces log identically.
 * commonMain default routes to println; platform source sets may override.
 */
object PlatformLogger {
    fun d(tag: String, msg: String) = println("D/$tag: $msg")
    fun i(tag: String, msg: String) = println("I/$tag: $msg")
    fun w(tag: String, msg: String) = println("W/$tag: $msg")
    fun e(tag: String, msg: String, t: Throwable? = null) {
        println("E/$tag: $msg")
        t?.printStackTrace()
    }
}
