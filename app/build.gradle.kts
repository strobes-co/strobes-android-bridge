plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "co.strobes.bridge"
    compileSdk = 34

    defaultConfig {
        applicationId = "co.strobes.bridge"
        minSdk = 26
        targetSdk = 34
        versionCode = 2
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
    }

    // Bouncy Castle's multi-release jars (bcprov/bcpkix/bcutil) all ship the
    // same META-INF/versions/9 manifest path — harmless duplication, just
    // needs a packaging rule to pick one instead of failing the merge.
    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/versions/9/module-info.class",
            )
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.lifecycle:lifecycle-service:2.8.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4") // repeatOnLifecycle
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // WebSocket client — same role as `websockets` in the Python daemon.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Root shell execution (Magisk/KernelSU su daemon aware). Falls back to a
    // bare `su -c` Process exec when no supported root manager is present.
    implementation("com.github.topjohnwu.libsu:core:6.0.0")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Pure-Java XZ decoder — frida-inject's GitHub releases ship .xz only;
    // this decompresses the on-demand per-ABI download (see FridaController)
    // without needing a native liblzma or shelling out to an `xz` binary
    // that plain Android doesn't ship.
    implementation("org.tukaani:xz:1.10")

    // Android's stock javax.security APIs can verify X.509 certs but not
    // ISSUE them — Bouncy Castle is what generates our root CA and the
    // per-host leaf certs the embedded MITM proxy signs on the fly.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")

    // Instrumented tests run ON-DEVICE — used to exercise ShellCommandRouter's
    // non-root path through StrobesAccessibilityService for real, the same
    // way BridgeWebSocketClient's shell_execute handler actually calls it,
    // instead of only verifying it compiles.
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}
