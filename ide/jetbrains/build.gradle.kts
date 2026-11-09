// OpenTine for JetBrains IDEs: an AI-blame gutter and "Verify this line's
// provenance", both built on the `tine` CLI. Every version below is pinned.
//
// `gradle test` runs the IDE-independent core (dev.opentine.ide.core) and
// `gradle buildPlugin` builds the plugin zip; both download the IntelliJ
// Platform, so CI does not run them (no JDK-and-network job). See README.md.

plugins {
    id("org.jetbrains.kotlin.jvm") version "2.0.21"
    id("org.jetbrains.intellij.platform") version "2.1.0"
}

group = "dev.opentine"
version = "0.0.0"

kotlin {
    jvmToolchain(17)
}

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        intellijIdeaCommunity("2024.2.4")
        instrumentationTools()
        testFramework(org.jetbrains.intellij.platform.gradle.TestFrameworkType.Platform)
    }
    // The platform bundles Gson; the core's unit tests need it on their own.
    compileOnly("com.google.code.gson:gson:2.11.0")
    testImplementation("com.google.code.gson:gson:2.11.0")
    testImplementation("junit:junit:4.13.2")
}

intellijPlatform {
    pluginConfiguration {
        id = "dev.opentine.ide"
        name = "OpenTine: AI blame and provenance"
        version = project.version.toString()
        ideaVersion {
            sinceBuild = "242"
            untilBuild = provider { null }
        }
    }
}
