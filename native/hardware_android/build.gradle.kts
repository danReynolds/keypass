plugins {
    id("com.android.library") version "8.8.0"
    id("org.jetbrains.kotlin.android") version "2.1.0"
}
android {
    namespace = "dev.keypass.hardware"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
        externalNativeBuild { cmake { cppFlags += "-std=c++17" } }
    }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
    implementation("com.yubico.yubikit:fido:2.9.0")
    implementation("androidx.startup:startup-runtime:1.2.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
}
