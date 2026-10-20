plugins {
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.androidKotlinMultiplatformLibrary) apply false
    alias(libs.plugins.jetbrainsKotlinJvm) apply false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    alias(libs.plugins.diffplugSpotless)
}

allprojects {
    apply(plugin = "com.diffplug.spotless")

    spotless {
        kotlin {
            target("src/**/*.kt")

            // Same ktlint and header as Amethyst, where this code started, so a file
            // moved between the two repos formats identically on both sides.
            ktlint("1.7.1")
            licenseHeaderFile(
                rootProject.file("spotless/copyright.kt"),
                "@file:|package|import|class|object|sealed|open|interface|abstract ",
            )
        }
    }
}

subprojects {
    afterEvaluate {
        // Kotlin Multiplatform registers no plain `test` task, so `./gradlew test` (the
        // pre-push hook) would skip :quic silently. Alias it onto jvmTest.
        if (plugins.hasPlugin("org.jetbrains.kotlin.multiplatform") &&
            tasks.findByName("test") == null &&
            tasks.findByName("jvmTest") != null
        ) {
            tasks.register("test") {
                group = "verification"
                description = "Runs the JVM unit tests for this Kotlin Multiplatform module."
                dependsOn("jvmTest")
            }
        }

        try {
            tasks.named("preBuild") {
                dependsOn("spotlessApply")
            }
        } catch (_: UnknownTaskException) {
            tasks.matching {
                it.name.startsWith("pre") && it.name.endsWith("Build")
            }.configureEach {
                dependsOn("spotlessApply")
            }
        }
    }
}

tasks.register<Copy>("installGitHook") {
    from("git-hooks/pre-commit")
    from("git-hooks/pre-push")
    into(".git/hooks")
    filePermissions { unix("rwxrwxrwx") }
}
