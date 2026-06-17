// Root build for the CIRISServer fabric app. Mirrors the plugin versions the
// CIRISAgent KMP client uses (Kotlin 2.0.21, AGP 8.5.2, Compose MP 1.7.1) so
// the copied fabric surfaces compile unchanged.
plugins {
    kotlin("multiplatform").version("2.0.21").apply(false)
    kotlin("android").version("2.0.21").apply(false)
    kotlin("plugin.serialization").version("2.0.21").apply(false)
    kotlin("plugin.compose").version("2.0.21").apply(false)

    id("com.android.application").version("8.5.2").apply(false)
    id("com.android.library").version("8.5.2").apply(false)

    id("org.jetbrains.compose").version("1.7.1").apply(false)
}

tasks.matching { it.name == "clean" }.configureEach {
    doLast {
        delete(rootProject.layout.buildDirectory)
    }
}
