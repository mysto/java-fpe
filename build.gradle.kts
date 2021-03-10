plugins {
    java
}

group = "org.example"
version = "0.8-SNAPSHOT"
java.sourceCompatibility = JavaVersion.VERSION_1_8

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("junit", "junit", "4.12")
    implementation("org.apache.logging.log4j:log4j-api:2.1")
}
