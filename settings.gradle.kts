pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// crypto-kmp (vitorpamplona/crypto-kmp) is released on Nostr + Blossom: the Magpie settings plugin
// serves its group, trusting only the release key vitorpamplona.com names as `releases`, and
// gradle/magpie.lock pins that key and every resolved version's files. It also puts the publish plugin
// (com.vitorpamplona.magpie.publish) on the classpath, so build scripts apply that one by id alone.
plugins {
    id("com.vitorpamplona.magpie") version "0.2.3"
}

magpie {
    group("com.vitorpamplona.crypto")
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
