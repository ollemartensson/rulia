plugins {
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.rulia:rulia-jvm:0.1.0")
}

application {
    mainClass.set("io.rulia.examples.SdkSurfaceDemo")
}
