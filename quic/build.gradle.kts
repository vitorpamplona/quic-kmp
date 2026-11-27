import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
    // Releases also go to Nostr + Blossom: publishToNostr. Its relays come from gradle.properties (magpie.*).
    id("com.vitorpamplona.magpie.publish")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    // iOS: the same protocol code over POSIX UDP sockets, crypto-kmp's AEADs and Apple's
    // Security framework for the server's certificate (src/nativeMain, src/appleMain).
    iosArm64()
    iosSimulatorArm64()

    // linuxX64 runs the native actuals where there is no Mac: -PquicNativeCheck adds it, so
    // `./gradlew -PquicNativeCheck :quic:linuxX64Test` runs commonTest over the POSIX sockets
    // (CI and the pre-push hook compile it). It is never published.
    val nativeCheck = providers.gradleProperty("quicNativeCheck").isPresent
    if (nativeCheck) {
        linuxX64()
    }

    android {
        namespace = "com.vitorpamplona.quic"
        compileSdk =
            libs.versions.android.compileSdk
                .get()
                .toInt()
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }

        withHostTest {}
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.kotlinx.coroutines.core)
                // Crypto primitives (HKDF, HMAC, SHA-256, AES-GCM, ChaCha20-Poly1305,
                // X25519) and the secure random source come from crypto-kmp. It is `api`
                // because TlsClient exposes X25519KeyPair.
                api(libs.crypto)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
            }
        }

        val jvmAndroid =
            create("jvmAndroid") {
                dependsOn(commonMain.get())
            }

        // The POSIX actuals, shared by iOS and the Linux check target; Apple's own (the Security
        // framework's certificate checks) above them. Explicit, because the jvmAndroid edge above
        // turns the default hierarchy template off.
        val nativeMain = maybeCreate("nativeMain").apply { dependsOn(commonMain.get()) }
        val appleMain = maybeCreate("appleMain").apply { dependsOn(nativeMain) }
        getByName("iosArm64Main").dependsOn(appleMain)
        getByName("iosSimulatorArm64Main").dependsOn(appleMain)
        if (nativeCheck) {
            getByName("linuxX64Main").dependsOn(nativeMain)
        }

        jvmMain {
            dependsOn(jvmAndroid)
        }

        androidMain {
            dependsOn(jvmAndroid)
        }

        jvmTest {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
                // QlogWriter writes qlog JSON; Jackson used to arrive through Quartz.
                implementation(libs.jackson.module.kotlin)
            }
        }

        getByName("androidHostTest") {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
            }
        }
    }
}

mavenPublishing {
    configure(
        KotlinMultiplatform(
            sourcesJar = SourcesJar.Sources(),
        ),
    )

    // groupId, artifactId, and version are configured via gradle.properties
    // (GROUP, POM_ARTIFACT_ID, VERSION_NAME) so CI can override VERSION_NAME
    // via ORG_GRADLE_PROJECT_VERSION_NAME without conflicting with a hardcoded value.

    publishToMavenCentral(automaticRelease = true)

    // Sign only when a key is configured: the release workflow passes one, while JitPack and
    // local publishToMavenLocal builds have none and would otherwise fail on the signing task.
    // Maven Central still rejects an unsigned upload, so a release can't slip out unsigned.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    pom {
        name = "QUIC for Kotlin Multiplatform"
        description = "Pure-Kotlin QUIC v1/v2 client and server, HTTP/3 and WebTransport for JVM, Android and iOS"
        inceptionYear = "2026"
        url = "https://github.com/vitorpamplona/quic-kmp/"
        licenses {
            license {
                name = "MIT License"
                url = "https://github.com/vitorpamplona/quic-kmp/blob/main/LICENSE"
            }
        }
        developers {
            developer {
                id = "vitorpamplona"
                name = "Vitor Pamplona"
                url = "http://vitorpamplona.com"
                email = "vitor@vitorpamplona.com"
            }
        }
        scm {
            url = "https://github.com/vitorpamplona/quic-kmp"
            connection = "https://github.com/vitorpamplona/quic-kmp.git"
        }
    }
}

/**
 * Run the live-interop runner against a real QUIC server. Configure target
 * via -PinteropHost=… -PinteropPort=… -PinteropTimeoutSec=…
 *
 * Usage:
 *   ./gradlew :quic:interop -PinteropHost=127.0.0.1 -PinteropPort=4433
 */
tasks.register<JavaExec>("interop") {
    group = "verification"
    description = "Drive QuicConnection against a real QUIC server (default 127.0.0.1:4433)."
    dependsOn("jvmTestClasses", "jvmJar")
    classpath =
        files(
            tasks.named("jvmJar"),
            configurations.named("jvmTestRuntimeClasspath"),
            layout.buildDirectory.dir("classes/kotlin/jvm/test"),
        )
    mainClass.set("com.vitorpamplona.quic.interop.InteropRunnerKt")
    val host = (project.findProperty("interopHost") as? String) ?: "127.0.0.1"
    val port = (project.findProperty("interopPort") as? String) ?: "4433"
    val timeoutSec = (project.findProperty("interopTimeoutSec") as? String) ?: "10"
    args(host, port)
    systemProperty("interopTimeoutSec", timeoutSec)
}

// Long-form audio-rooms soak test. Disabled by default — `./gradlew test`
// must stay fast for CI. Opt in with `-PquicSoakSeconds=N` (e.g. 1800 for
// the 30-minute run from the soak prompt). Without the property the test
// class checks for null and skips via `Assume.assumeTrue`.
tasks.withType<Test>().configureEach {
    val soakSeconds = (project.findProperty("quicSoakSeconds") as? String)
    if (soakSeconds != null) {
        systemProperty("quicSoakSeconds", soakSeconds)
    }
}
