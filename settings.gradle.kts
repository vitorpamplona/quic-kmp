pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "quic-kmp"

// crypto-kmp lives in its own repo (vitorpamplona/crypto-kmp) and comes from Maven Central. To
// change it alongside quic, point Gradle at a local checkout and it builds that checkout
// instead of the published artifact:
//   ./gradlew -PcryptoKmpDir=../crypto-kmp :quic:jvmTest
providers.gradleProperty("cryptoKmpDir").orNull?.let { dir ->
    includeBuild(dir) {
        dependencySubstitution {
            substitute(module("com.vitorpamplona.crypto:crypto")).using(project(":crypto"))
        }
    }
}
include(":quic")

// quic-interop-runner endpoint (JVM app + Docker image); never published.
include(":quic-interop")
project(":quic-interop").projectDir = file("interop")
