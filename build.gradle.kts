plugins {
    java
    // id("me.champeau.jmh") version "0.6.6"
}

group = "com.privacylogistics"
version = "0.8.1"
java.sourceCompatibility = JavaVersion.VERSION_1_8

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("junit", "junit", "4.12")
    implementation("org.apache.logging.log4j:log4j-api:2.1")
}
