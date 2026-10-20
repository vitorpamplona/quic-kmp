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
include(":quic")

// quic-interop-runner endpoint (JVM app + Docker image); never published.
include(":quic-interop")
project(":quic-interop").projectDir = file("quic/interop")
