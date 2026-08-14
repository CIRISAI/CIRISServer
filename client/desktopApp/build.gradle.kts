import org.jetbrains.compose.desktop.application.dsl.TargetFormat

// ─── The native-distribution version, DERIVED (CIRISServer#403) ─────────────
//
// This is packaging metadata only: it names the Dmg/Msi/Deb bundle and, as a
// side effect, the uber-JAR's filename. It is NOT the client's identity — that
// is `CLIENT_VERSION` in shared/…/models/ClientMode.kt, which is what the
// node-vs-client banner compares and what `scripts/sync-client-version.sh`
// keeps in lockstep with Cargo.toml.
//
// It was the hardcoded string "2.6.0" from the day the client was vendored
// (v0.5.4) until 0.5.171 — never bumped, and worse than merely stale: 2.6.0 is
// a real CIRISAgent release, so every JAR filename, build log and bug report
// read as "agent 2.6.0". One string, two meanings, on a version number.
//
// It cannot simply BE the release version: compose-desktop refuses a 0.x major
// for Dmg ("Illegal version for 'Dmg': '0.5.171' is not a valid version"),
// because macOS CFBundleVersion requires a major ≥ 1. So the major is forced to
// 1 and the rest tracks the release digit for digit — 0.5.171 → 1.5.171. Being
// derived is the point: there is nothing left to forget to bump.
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
            description = "CIRIS Agent Desktop Application"
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

// Sync localization JSON files from main repo to resources
tasks.register<Sync>("syncLocalizationResources") {
    description = "Sync localization JSON files from main repo to resources"
    from("../../localization") {
        include("*.json")
        exclude("manifest.json")
    }
    into("src/main/resources/localization")
}

// Ensure localization resources are synced before processing resources
tasks.named("processResources") {
    dependsOn("syncLocalizationResources")
}
