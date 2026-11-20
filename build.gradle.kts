plugins {
    java
    alias(libs.plugins.runvelocity)
    alias(libs.plugins.idea.ext)
    alias(libs.plugins.blossom)
    alias(libs.plugins.shadow)
}

repositories {
    maven("https://repo.papermc.io/repository/maven-public/")
}

dependencies {
    compileOnly(libs.velocity)
    compileOnly(libs.luckperms)
    annotationProcessor(libs.velocity)
    
    implementation(libs.nimbus.oauth2.oidc.sdk)
    implementation(libs.guava)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.gson)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        showStandardStreams = true
    }
}

tasks {
    compileJava {
        options.encoding = Charsets.UTF_8.name()
        options.release.set(25)
    }
    shadowJar {
        archiveClassifier.set("")
        mergeServiceFiles()
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
        relocate("com.nimbusds", "io.github.lulle2007200.oauthgate.libs.com.nimbusds")
        relocate("net.minidev", "io.github.lulle2007200.oauthgate.libs.net.minidev")
        relocate("com.github.stephenc", "io.github.lulle2007200.oauthgate.libs.com.github.stephenc")
    }
    clean {
        delete("run")
    }
    runVelocity {
        velocityVersion(libs.versions.velocity.get())
    }
}

sourceSets {
    main {
        blossom {
            javaSources {
                property("version", project.version.toString())
                property("name", project.name.toString())
                property("id", providers.gradleProperty("id"))
                property("author", providers.gradleProperty("author"))
                property("description", project.description.toString())
            }
        }
    }
}

java.toolchain.languageVersion.set(JavaLanguageVersion.of(25))