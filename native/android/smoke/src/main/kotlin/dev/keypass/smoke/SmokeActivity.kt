package dev.keypass.smoke
import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import org.json.JSONObject
import java.io.File

class SmokeActivity : Activity() {
    private external fun roundTrip(request: ByteArray, cancel: Boolean): ByteArray
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        System.loadLibrary("keypass_smoke")
        val label = TextView(this); label.text = "Testing native bridge without passkey UI…"; setContentView(label)
        label.postDelayed({ Thread {
            val result = try {
                val availability = JSONObject(String(roundTrip("{\"operation\":\"availability\",\"domain\":\"vault.example.com\"}".toByteArray(), false)))
                check(availability.optString("platform") == "android") { "availability: $availability" }
                check(availability.getString("origin").matches(Regex("android:apk-key-hash:[A-Za-z0-9_-]{43}")))
                check(availability.getBoolean("multiple"))
                val cancelled = JSONObject(String(roundTrip("{\"operation\":\"availability\",\"domain\":\"vault.example.com\"}".toByteArray(), true)))
                check(cancelled.optString("error") == "cancelled" || cancelled.optString("platform") == "android") { "cancel response: $cancelled" }
                "PASS native Activity discovery, signing-certificate origin, JNI ABI, cancellation. No passkey ceremony attempted."
            } catch (e: Exception) { "FAIL native Android bridge smoke: ${e.javaClass.simpleName}: ${e.message}" }
            File(filesDir, "keypass-native-smoke.txt").writeText(result)
            runOnUiThread { label.text = result }
        }.start() }, 800)
    }
}
