import org.jetbrains.compose.desktop.application.dsl.TargetFormat

// ─── NODE VENDOR DRIFT #35 (restored after the 2.9.28 re-vendor hardcoded the
// AGENT's version here): the native-distribution version, DERIVED
// (CIRISServer#403) ──────────────────────────────────────────────────────────
//
// This is packaging metadata only: it names the Dmg/Msi/Deb bundle and, as a
// side effect, the uber-JAR's filename. It is NOT the client's identity — that
// is `CLIENT_VERSION` in shared/…/models/ClientMode.kt.
//
// It was the hardcoded string "2.6.0" from vendoring day until 0.5.171 — a
// real CIRISAgent release number, so every JAR filename and bug report read as
// "agent 2.6.0". The re-vendor reintroduced EXACTLY that defect as "2.9.28",
// with a sharper edge: shipped once, native upgraders (MSI especially) treat
// the next real 1.5.x as a DOWNGRADE and refuse it.
//
// It cannot simply BE the release version: compose-desktop refuses a 0.x major
// for Dmg (macOS CFBundleVersion requires major >= 1), so the major is forced
// to 1 and the rest tracks the release digit for digit — 0.5.185 -> 1.5.185.
// Being derived is the point: there is nothing left to forget to bump.
val releaseVersion: String =
    Regex("""^version = "([^"]+)"""", RegexOption.MULTILINE)
        .find(rootProject.file("../Cargo.toml").readText())
        ?.groupValues
        ?.get(1)
        ?: error("could not read [package] version from Cargo.toml")

val nativePackageVersion: String =
    releaseVersion.split('.').let { parts ->
        require(parts.size >= 3) { "release version '$releaseVersion' is not major.minor.patch" }
        // Only the major is coerced, and only because the format forbids 0.
        val major = parts[0].toIntOrNull() ?: error("non-numeric major in '$releaseVersion'")
        "${maxOf(major, 1)}.${parts[1]}.${parts[2]}"
    }

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    kotlin("plugin.compose")
    id("org.jetbrains.compose")
}

dependencies {
    implementation(project(":shared"))
    implementation(compose.desktop.currentOs)
    implementation(compose.runtime)
    implementation(compose.foundation)
    implementation(compose.material3)

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.8.0")

    // Test automation server (Ktor embedded) - must match shared module version
    val ktorVersion = "3.0.3"
    implementation("io.ktor:ktor-server-core:$ktorVersion")
    implementation("io.ktor:ktor-server-cio:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")
    implementation("io.ktor:ktor-server-status-pages:$ktorVersion")
}

compose.desktop {
    application {
        mainClass = "ai.ciris.desktop.MainKt"

        nativeDistributions {
            targetFormats(TargetFormat.Dmg, TargetFormat.Msi, TargetFormat.Deb)
            packageName = "CIRIS"
            packageVersion = nativePackageVersion
            description = "CIRIS Node Desktop Application"
            vendor = "CIRIS L3C"

            macOS {
                bundleID = "ai.ciris.desktop"
                iconFile.set(project.file("icons/icon.icns"))
            }

            windows {
                iconFile.set(project.file("icons/icon.ico"))
                menuGroup = "CIRIS"
                upgradeUuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            }

            linux {
                iconFile.set(project.file("icons/icon.png"))
            }
        }
    }
}

kotlin {
    jvmToolchain(17)
}

// NODE VENDOR DRIFT #9 (CIRISServer#465): upstream's syncLocalizationResources
// is REMOVED — same destination-owning Sync hazard as androidApp's
// syncLocalizationAssets (see that file's comment for the full account).
