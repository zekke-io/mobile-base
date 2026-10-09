import com.android.build.api.withAndroid
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.HostManager

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.sqldelight)
    alias(libs.plugins.android.kotlin.multiplatform.library)
}

abstract class NativeLibraryBuild : Exec() {
    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty
}

abstract class GenerateTestFixturesSource : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val fixtures: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val constants = fixtures.get().asFile.listFiles { file -> file.extension == "json" }!!.sortedBy { it.name }.map { fixture ->
            val json = fixture.readText()
            check(!json.contains("\"\"\"")) { "${fixture.name} cannot be embedded in a raw string" }
            val name = fixture.nameWithoutExtension.uppercase().replace(Regex("[^A-Z0-9]"), "_") + "_JSON"
            val parts = json.chunked(20_000).joinToString(",\n") { "\"\"\"" + it.replace("$", "\${'$'}") + "\"\"\"" }
            "internal val $name: String = listOf(\n$parts,\n).joinToString(\"\")\n"
        }
        val source = outputDirectory.get().file("zekke/core/fixtures/TestFixtures.kt").asFile
        outputDirectory.get().asFile.deleteRecursively()
        source.parentFile.mkdirs()
        source.writeText("package zekke.core.fixtures\n\n" + constants.joinToString("\n"))
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

val generateTestFixturesSource = tasks.register<GenerateTestFixturesSource>("generateTestFixturesSource") {
    fixtures.set(layout.projectDirectory.dir("src/commonTest/fixtures"))
    outputDirectory.set(layout.buildDirectory.dir("generated/testFixtures/kotlin"))
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

    android {
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
            implementation(libs.kotlinx.serialization.json)
            api(libs.kotlinx.coroutines.core)
            implementation(libs.ktor.client.core)
            implementation(libs.sqldelight.runtime)
        }
        commonTest {
            kotlin.srcDir(generateTestFixturesSource)
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.kotlinx.coroutines.test)
                implementation(libs.ktor.client.mock)
            }
        }
        jvmMain.dependencies {
            implementation(libs.cryptography.provider.jdk)
            implementation(libs.bouncycastle.provider)
            implementation(libs.ktor.client.okhttp)
            implementation(libs.sqldelight.sqlite.driver)
        }
        androidMain.dependencies {
            implementation(libs.cryptography.provider.jdk)
            implementation(libs.bouncycastle.provider)
            implementation(libs.ktor.client.okhttp)
            implementation(libs.sqldelight.android.driver)
        }
        iosMain.dependencies {
            implementation(libs.cryptography.provider.apple)
            implementation(libs.cryptography.provider.cryptokit)
            implementation(libs.ktor.client.darwin)
            implementation(libs.sqldelight.native.driver)
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
    filter { excludeTestsMatching("zekke.core.interop.*") }
    val libraryFile = nativeBuildDirectory.map { it.file("jvm/" + System.mapLibraryName("zekke_native")).asFile.absolutePath }
    doFirst { systemProperty("zekke.native.library", libraryFile.get()) }
}

val jvmInteropTest = tasks.register<Test>("jvmInteropTest") {
    group = "verification"
    description = "Runs the interop suite against a running Zekke API (ZEKKE_INTEROP_API, default http://localhost:8080)."
    val jvmTest = tasks.named<Test>("jvmTest")
    testClassesDirs = files(jvmTest.map { it.testClassesDirs })
    classpath = files(jvmTest.map { it.classpath })
    dependsOn(buildJvmNativeLibrary, "jvmTestClasses")
    useJUnit()
    filter { includeTestsMatching("zekke.core.interop.*") }
    systemProperty("zekke.interop.api", providers.environmentVariable("ZEKKE_INTEROP_API").getOrElse("http://localhost:8080"))
    systemProperty("zekke.crossclient.dir", providers.environmentVariable("ZEKKE_CROSSCLIENT_DIR").getOrElse(""))
    systemProperty("zekke.crossclient.step", providers.environmentVariable("ZEKKE_CROSSCLIENT_STEP").getOrElse(""))
    providers.environmentVariable("ZEKKE_INTEROP_DRIVE_BYTES").orNull?.let { systemProperty("zekke.interop.driveBytes", it) }
    outputs.upToDateWhen { false }
    val libraryFile = nativeBuildDirectory.map { it.file("jvm/" + System.mapLibraryName("zekke_native")).asFile.absolutePath }
    doFirst { systemProperty("zekke.native.library", libraryFile.get()) }
}

tasks.named("check") {
    dependsOn(checkTestVectorsFixture)
}

tasks.matching { it.name.startsWith("cinteropZekkeNative") }.configureEach {
    dependsOn(buildIosNativeLibraries)
}

sqldelight {
    databases {
        create("ReplicaDatabase") {
            packageName.set("zekke.core.feed.db")
            srcDirs("src/commonMain/sqldelight/replica")
        }
        create("OutboxDatabase") {
            packageName.set("zekke.core.feed.outboxdb")
            srcDirs("src/commonMain/sqldelight/outbox")
        }
    }
}
