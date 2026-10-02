plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "dev.keypass.smoke"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    defaultConfig { applicationId = "dev.keypass.smoke"; minSdk = 28; targetSdk = 35; versionCode = 1; versionName = "1" }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
dependencies { implementation(project(":")) }
