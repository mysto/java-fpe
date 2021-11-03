plugins {
    java
    // id("me.champeau.jmh") version "0.6.6"
}

group = "com.privacylogistics"
version = "1.0.0"
java.sourceCompatibility = JavaVersion.VERSION_1_8

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("junit", "junit", "4.12")
    implementation("org.apache.logging.log4j:log4j-api:2.1")
}

tasks.jar {
    archiveFileName.set("ff3.jar")
}
