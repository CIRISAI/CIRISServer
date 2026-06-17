import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// fabric-client — the CIRISServer mesh/fabric KMP client.
//
// Surfaces copied from the CIRISAgent KMP client (client/shared) MINUS the
// agent cards (chat / runtime / billing / cognitive-state / persona). Repointed
// at CIRISServer's REAL endpoints:
//   - GET /v1/identity  → persist LocalIdentityAggregate (six-key), served by
//     src/compose.rs::identity_router on the lens read-API listener.
//   - GET /lens/api/v1/* → the frozen lens read API (crates/ciris-lens-core).
//   - federation directory / content / trust / consent / governance surfaces
//     land as the registry (Server 0.5) + node (Server 1.0) slices fold in.
//
// Auth model is CIRISServer's federation-signed request contract
// (x-ciris-signing-key-id / x-ciris-signature-ed25519 / x-ciris-signature-ml-dsa-65
// over the request BODY), NOT the Bearer-token auth the CIRISAgent client used.
// See net/FederationSignedAuth.kt + crates/ciris-lens-core/src/role/node.rs.
plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.library")
    id("org.jetbrains.compose")
    kotlin("plugin.compose")
}

kotlin {
    targets.all {
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions {
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                }
            }
        }
    }

    androidTarget {
        compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
    }

    listOf(iosX64(), iosArm64(), iosSimulatorArm64()).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "fabric"
            isStatic = true
        }
    }

    jvm("desktop") {
        compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
    }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        moduleName = "ciris-fabric"
        browser {
            commonWebpackConfig { outputFileName = "ciris-fabric.js" }
        }
        binaries.executable()
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(compose.runtime)
                implementation(compose.foundation)
                implementation(compose.material3)
                implementation(compose.components.resources)

                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.1")

                implementation("io.ktor:ktor-client-core:3.0.3")
                implementation("io.ktor:ktor-client-content-negotiation:3.0.3")
                implementation("io.ktor:ktor-serialization-kotlinx-json:3.0.3")
                implementation("io.ktor:ktor-client-logging:3.0.3")

                implementation("org.jetbrains.androidx.lifecycle:lifecycle-viewmodel-compose:2.8.4")
                implementation("org.jetbrains.androidx.lifecycle:lifecycle-runtime-compose:2.8.4")
            }
        }
        val androidMain by getting {
            dependencies {
                implementation("io.ktor:ktor-client-okhttp:3.0.3")
            }
        }
        val iosMain by creating {
            dependsOn(commonMain)
            dependencies { implementation("io.ktor:ktor-client-darwin:3.0.3") }
        }
        val iosX64Main by getting { dependsOn(iosMain) }
        val iosArm64Main by getting { dependsOn(iosMain) }
        val iosSimulatorArm64Main by getting { dependsOn(iosMain) }
        val desktopMain by getting {
            dependencies {
                implementation(compose.desktop.currentOs)
                implementation("io.ktor:ktor-client-cio:3.0.3")
            }
        }
        val wasmJsMain by getting {
            dependencies { implementation("io.ktor:ktor-client-js:3.0.3") }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
                implementation("io.ktor:ktor-client-mock:3.0.3")
            }
        }
    }
}

android {
    namespace = "ai.ciris.fabric"
    compileSdk = 34
    defaultConfig { minSdk = 24 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
