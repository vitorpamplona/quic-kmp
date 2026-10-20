import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
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

    // commonMain must stay platform-neutral, but with only JVM-family targets Kotlin
    // lets it use JVM APIs and its metadata compile checks nothing. -PquicNativeCheck
    // adds a native target, which turns commonMain and commonTest into real common
    // code, so `./gradlew -PquicNativeCheck :quic:compileTestKotlinLinuxX64` (CI and
    // the pre-push hook) catches a JVM-only call in either. Its actuals are throwing
    // placeholders (src/nativeCheck): never run or publish it.
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
                // X25519) and the secure random source come from Quartz.
                api(libs.quartz)
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

        if (nativeCheck) {
            // Throwing placeholder actuals, so the check target builds and commonTest
            // compiles too: `./gradlew -PquicNativeCheck :quic:compileTestKotlinLinuxX64`.
            getByName("linuxX64Main").kotlin.srcDir("src/nativeCheck/kotlin")
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
                implementation(libs.secp256k1.kmp.jni.jvm)
            }
        }

        getByName("androidHostTest") {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
                implementation(libs.secp256k1.kmp.jni.jvm)
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

    signAllPublications()

    pom {
        name = "QUIC for Kotlin Multiplatform"
        description = "Pure-Kotlin QUIC v1, HTTP/3 and WebTransport client for JVM and Android"
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
