import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.jetbrainsKotlinJvm)
    application
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
    }
}

sourceSets {
    main {
        kotlin.srcDir("src/main/kotlin")
    }
    test {
        kotlin.srcDir("src/test/kotlin")
    }
}

dependencies {
    implementation(project(":quic"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.jackson.module.kotlin)

    testImplementation(libs.kotlin.test)
}

application {
    mainClass.set("com.vitorpamplona.quic.interop.runner.InteropClientKt")
    applicationName = "quic-interop"
}
