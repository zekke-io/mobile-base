import com.android.build.api.withAndroid
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.HostManager

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
}

abstract class NativeLibraryBuild : Exec() {
    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty
}

abstract class GenerateTestVectorsSource : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val fixture: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val json = fixture.get().asFile.readText()
        check(!json.contains("\"\"\"")) { "the fixture cannot be embedded in a raw string" }
        val source = outputDirectory.get().file("zekke/core/fixtures/TestVectorsJson.kt").asFile
        source.parentFile.mkdirs()
        source.writeText(
            "package zekke.core.fixtures\n\ninternal const val TEST_VECTORS_JSON = \"\"\"" +
                json.replace("$", "\${'$'}") + "\"\"\"\n",
        )
    }
}

abstract class CheckTestVectorsFixture : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val fixture: RegularFileProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val authority: ConfigurableFileCollection

    @TaskAction
    fun compare() {
        val authorityFile = authority.singleOrNull { it.exists() }
        if (authorityFile == null) {
            logger.lifecycle("api-general is not checked out next to mobile-base: the vector fixture was not compared.")
            return
        }
        check(authorityFile.readBytes().contentEquals(fixture.get().asFile.readBytes())) {
            "src/commonTest/fixtures/test-vectors.json differs from api-general/docs/crypto/test-vectors.json: copy it again."
        }
    }
}

val nativeDirectory = layout.projectDirectory.dir("native")
val nativeBuildDirectory = layout.buildDirectory.dir("native")
val nativeSources = files(
    nativeDirectory.dir("src"),
    nativeDirectory.file("lib.sh"),
    nativeDirectory.file("sources.env"),
)

fun NativeLibraryBuild.configureScript(script: String, outputSubdirectory: String) {
    group = "native"
    if (name != "fetchNativeSources") dependsOn("fetchNativeSources")
    inputs.files(nativeSources).withPropertyName("nativeSources")
    inputs.file(nativeDirectory.file(script)).withPropertyName("buildScript")
    outputDirectory.set(nativeBuildDirectory.map { it.dir(outputSubdirectory) })
    environment("NATIVE_BUILD_DIR", nativeBuildDirectory.get().asFile.absolutePath)
    commandLine("bash", nativeDirectory.file(script).asFile.absolutePath)
}

val testVectorsFixture = layout.projectDirectory.file("src/commonTest/fixtures/test-vectors.json")

val generateTestVectorsSource = tasks.register<GenerateTestVectorsSource>("generateTestVectorsSource") {
    fixture.set(testVectorsFixture)
    outputDirectory.set(layout.buildDirectory.dir("generated/testVectors/kotlin"))
}

val checkTestVectorsFixture = tasks.register<CheckTestVectorsFixture>("checkTestVectorsFixture") {
    group = "verification"
    description = "Fails when the vector fixture has drifted from api-general's test-vectors.json."
    fixture.set(testVectorsFixture)
    authority.from(layout.projectDirectory.file("../api-general/docs/crypto/test-vectors.json"))
}

val fetchNativeSources = tasks.register<NativeLibraryBuild>("fetchNativeSources") {
    description = "Downloads libsodium and mlkem-native and checks them against their pinned SHA-256."
    configureScript("fetch.sh", "src")
}

val buildJvmNativeLibrary = tasks.register<NativeLibraryBuild>("buildJvmNativeLibrary") {
    description = "Builds libsodium, mlkem-native and the JNI shim for the host JVM."
    configureScript("build-jvm.sh", "jvm")
    environment("JAVA_HOME", javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }
        .get().metadata.installationPath.asFile.absolutePath)
}

val buildAndroidNativeLibraries = tasks.register<NativeLibraryBuild>("buildAndroidNativeLibraries") {
    description = "Builds libsodium, mlkem-native and the JNI shim for every Android ABI with the NDK."
    configureScript("build-android.sh", "android/jniLibs")
    environment("ANDROID_MIN_SDK", libs.versions.android.min.sdk.get())
    environment("ANDROID_NDK_VERSION", libs.versions.android.ndk.get())
}

val buildIosNativeLibraries = tasks.register<NativeLibraryBuild>("buildIosNativeLibraries") {
    description = "Builds libsodium, mlkem-native and the C surface as static libraries for iOS."
    configureScript("build-ios.sh", "ios")
    onlyIf { HostManager.hostIsMac }
}

kotlin {
    jvmToolchain(21)

    jvm()

    androidLibrary {
        namespace = "zekke.core"
        compileSdk = libs.versions.android.compile.sdk.get().toInt()
        minSdk = libs.versions.android.min.sdk.get().toInt()

        optimization {
            consumerKeepRules.publish = true
            consumerKeepRules.file("consumer-rules.pro")
        }

        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    listOf(iosArm64(), iosSimulatorArm64()).forEach { target: KotlinNativeTarget ->
        target.compilations.getByName("main").cinterops.create("zekkeNative") {
            definitionFile.set(project.file("src/nativeInterop/cinterop/zekkeNative.def"))
            includeDirs(nativeDirectory.dir("src").asFile)
            extraOpts("-libraryPath", nativeBuildDirectory.get().dir("ios/${target.name}").asFile.absolutePath)
        }
    }

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            group("jni") {
                withJvm()
                withAndroid()
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.cryptography.core)
        }
        commonTest {
            kotlin.srcDir(generateTestVectorsSource)
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.kotlinx.serialization.json)
            }
        }
        jvmMain.dependencies {
            implementation(libs.cryptography.provider.jdk)
            implementation(libs.bouncycastle.provider)
        }
        androidMain.dependencies {
            implementation(libs.cryptography.provider.jdk)
            implementation(libs.bouncycastle.provider)
        }
        iosMain.dependencies {
            implementation(libs.cryptography.provider.apple)
            implementation(libs.cryptography.provider.cryptokit)
        }
        getByName("androidDeviceTest").dependencies {
            implementation(libs.androidx.test.runner)
        }
    }

    compilerOptions {
        allWarningsAsErrors.set(true)
        optIn.add("dev.whyoleg.cryptography.DelicateCryptographyApi")
    }
}

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(buildAndroidNativeLibraries, NativeLibraryBuild::outputDirectory)
    }
}

tasks.named<Test>("jvmTest") {
    dependsOn(buildJvmNativeLibrary)
    val libraryFile = nativeBuildDirectory.map { it.file("jvm/" + System.mapLibraryName("zekke_native")).asFile.absolutePath }
    doFirst { systemProperty("zekke.native.library", libraryFile.get()) }
}

tasks.named("check") {
    dependsOn(checkTestVectorsFixture)
}

tasks.matching { it.name.startsWith("cinteropZekkeNative") }.configureEach {
    dependsOn(buildIosNativeLibraries)
}
