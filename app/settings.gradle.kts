// CIRISServer fabric app — the KMP mesh/fabric client.
//
// CIRISServer#15: "agent app = fabric app (CIRISServer) + agent cards".
// This module is the *fabric app* half — the complete mesh/fabric surfaces
// (identity, federation directory, content fetch, trust, consent, governance,
// CEG-native erasure). The agent reasoning/persona "cards" stay in CIRISAgent
// and are NOT part of this module.
//
// Standalone Gradle build (its own settings.gradle.kts) so it does NOT couple
// to the Rust/Cargo workspace at the repo root. Open `app/` in an IDE to build
// the KMP client; `cargo` at the repo root is unaffected.
rootProject.name = "ciris-fabric-app"

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

include(":fabric-client")
