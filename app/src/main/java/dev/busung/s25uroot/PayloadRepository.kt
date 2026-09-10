package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

class PayloadRepository(private val context: Context) {
    fun loadTargets(): List<TargetProfile> {
        if (BuildConfig.FEED_LOCAL) {
            val manifestBytes = readAsset(
                "$LOCAL_ASSET_ROOT/support/targets-v3.json",
                MAX_MANIFEST_BYTES,
            )
            return SupportManifest.parse(manifestBytes).targets
        }
        val commit = resolveMainCommit()
        val manifestBytes = downloadBytes(rawUrl(commit, "support/targets-v3.json"), MAX_MANIFEST_BYTES)
        return SupportManifest.parse(manifestBytes).targets.map { profile -> profile.copy(
            exploit = profile.exploit.copy(url = pinArtifactUrl(profile.exploit.url, commit)),
            kernelSu = profile.kernelSu.copy(url = pinArtifactUrl(profile.kernelSu.url, commit)),
        ) }
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile {
        val targets = loadTargets()
        // Prefer an exact full-kernel-release match so regional builds that share
        // a model and the three-part kernel version (e.g. SM-S9360 ZCS vs ZHS)
        // resolve to the correct profile; fall back to the legacy three-part match.
        return targets.firstOrNull {
            it.matchesDevice(snapshot) && snapshot.kernelRelease in it.kernelVersions
        } ?: targets.firstOrNull { it.matches(snapshot) }
        ?: error(context.getString(R.string.repo_no_profile))
    }

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = downloadArtifact(
            profile.exploit,
            File(directory, "cve-2026-43499-app.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = downloadArtifact(
            profile.kernelSu,
            File(directory, "ksud-s25u-kdp"),
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(
            context.getString(
                if (BuildConfig.FEED_LOCAL) R.string.repo_staging else R.string.repo_downloading,
                label,
            ),
        )
        val temporary = File(destination.parentFile, "${destination.name}.part")
        if (BuildConfig.FEED_LOCAL) {
            copyBundledArtifact(artifact, temporary, label)
        } else {
            fetchRemoteArtifact(artifact, temporary, label)
        }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun copyBundledArtifact(artifact: RemoteArtifact, temporary: File, label: String) {
        var total = 0L
        openAsset(bundledAssetPath(artifact.url)).use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
    }

    private fun fetchRemoteArtifact(artifact: RemoteArtifact, temporary: File, label: String) {
        val connection = open(artifact.url)
        require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
            context.getString(R.string.repo_size_mismatch, label)
        }
        var total = 0L
        connection.inputStream.use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        connection.disconnect()
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
    }

    private fun resolveMainCommit(): String {
        val response = downloadBytes(COMMIT_API_URL, MAX_COMMIT_RESPONSE_BYTES)
        val commit = JSONObject(response.toString(Charsets.UTF_8))
            .getJSONObject("object")
            .getString("sha")
        require(commit.matches(Regex("[0-9a-f]{40}"))) { context.getString(R.string.repo_commit_invalid) }
        return commit
    }

    private fun rawUrl(commit: String, path: String) = "$RAW_REPOSITORY/$commit/$path"

    private fun pinArtifactUrl(url: String, commit: String): String {
        // Accept a GitHub raw URL or a LAN feed URL and re-pin it to the
        // configured feed base at the resolved commit. The path after
        // "/<ref>/" is preserved, so the manifest can keep upstream URLs.
        val marker = "/${BuildConfig.FEED_REF}/"
        val index = url.indexOf(marker)
        require(index >= 0) { context.getString(R.string.repo_url_invalid) }
        val path = url.substring(index + marker.length)
        require(path.isNotBlank()) { context.getString(R.string.repo_url_invalid) }
        return "$RAW_REPOSITORY/$commit/$path"
    }

    private fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    /**
     * Maps a manifest artifact URL to its bundled asset. Local builds use
     * `local://<path>`; a GitHub-style URL is accepted too so a manifest can
     * be swapped in without rewriting every artifact entry.
     */
    private fun bundledAssetPath(url: String): String {
        val relative = if (url.startsWith(LOCAL_URL_SCHEME)) {
            url.removePrefix(LOCAL_URL_SCHEME)
        } else {
            val marker = "/${BuildConfig.FEED_REF}/"
            val index = url.indexOf(marker)
            require(index >= 0) { context.getString(R.string.repo_url_invalid) }
            url.substring(index + marker.length)
        }
        require(relative.isNotBlank() && !relative.split('/').contains("..")) {
            context.getString(R.string.repo_url_invalid)
        }
        return "$LOCAL_ASSET_ROOT/$relative"
    }

    private fun openAsset(path: String): InputStream = try {
        context.assets.open(path)
    } catch (_: FileNotFoundException) {
        error(context.getString(R.string.repo_asset_missing, path))
    }

    private fun readAsset(path: String, maximum: Int): ByteArray =
        openAsset(path).use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    companion object {
        private const val LOCAL_ASSET_ROOT = "feed"
        private const val LOCAL_URL_SCHEME = "local://"
        private val COMMIT_API_URL = BuildConfig.FEED_COMMIT_API
        private val RAW_REPOSITORY = BuildConfig.FEED_RAW_BASE
        private const val MAX_COMMIT_RESPONSE_BYTES = 16 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}
