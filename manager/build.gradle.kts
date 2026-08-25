plugins {
    alias(libs.plugins.agp.app) apply false
    alias(libs.plugins.kotlin) apply false
    alias(libs.plugins.compose.compiler) apply false
}

extra["androidMinSdkVersion"] = 31
extra["androidTargetSdkVersion"] = 37
extra["androidCompileSdkVersion"] = 37
extra["androidCompileSdkVersionMinor"] = 0
extra["androidBuildToolsVersion"] = "37.0.0"
extra["androidCompileNdkVersion"] = libs.versions.ndk.get()
extra["androidSourceCompatibility"] = JavaVersion.VERSION_21
extra["androidTargetCompatibility"] = JavaVersion.VERSION_21
extra["managerVersionCode"] = getVersionCode()
extra["managerVersionName"] = getVersionName()

fun getGitCommitCount(): Int {
    val process = Runtime.getRuntime().exec(arrayOf("git", "rev-list", "--count", "HEAD"))
    return process.inputStream.bufferedReader().use { it.readText().trim().toInt() }
}

fun getGitDescribe(): String {
    val process = Runtime.getRuntime().exec(arrayOf("git", "describe", "--tags", "--always"))
    return process.inputStream.bufferedReader().use { it.readText().trim() }
}

fun getVersionCode(): Int {
    // On tag builds (CI release), use a semantic version code so a release is
    // always newer than any branch build from the same commit count.
    // vMAJOR.MINOR.PATCH -> MAJOR*10000 + MINOR*100 + PATCH (e.g. v4.1.6 -> 40106)
    if (System.getenv("GITHUB_REF_TYPE") == "tag") {
        val tag = System.getenv("GITHUB_REF_NAME") ?: ""
        val m = Regex("^v(\\d+)\\.(\\d+)\\.(\\d+)$").find(tag)
        if (m != null) {
            return m.groupValues[1].toInt() * 10000 +
                m.groupValues[2].toInt() * 100 +
                m.groupValues[3].toInt()
        }
    }
    val commitCount = getGitCommitCount()
    return 30000 + commitCount
}

fun getVersionName(): String {
    return getGitDescribe()
}
