package co.strobes.bridge

import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.widget.TableLayout
import android.widget.TableRow
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

/**
 * Standalone "what works with and without root" reference — reachable from
 * the main screen and as a step in OnboardingActivity. A real table (not
 * prose) because the whole point is quick side-by-side scanning, not reading.
 */
class CapabilityTableActivity : AppCompatActivity() {

    private data class Row(val capability: String, val root: String, val nonRoot: String, val nonRootOk: Boolean)

    private val rows = listOf(
        Row("Arbitrary shell command", "Yes", "No", false),
        Row("Tap / swipe / type", "Yes (input/shell)", "Yes (Accessibility)", true),
        Row("Screenshot", "Yes", "Yes (Android 11+)", true),
        Row("UI hierarchy dump", "Yes", "Yes (Accessibility)", true),
        Row("Launch app by package", "Yes", "Yes (monkey launcher)", true),
        Row("List installed packages", "Yes", "Yes (PackageManager)", true),
        Row("Network info", "Yes", "Yes (ConnectivityManager)", true),
        Row("Arbitrary file read/write", "Yes (any path)", "No (sandboxed VirtualFs only)", false),
        Row("Traffic interception (MITM)", "Yes", "No — no VPN-based fallback yet", false),
        Row("CA cert trust", "Yes (auto, no dialog)", "Yes (KeyChain dialog, user taps confirm)", true),
        Row("System-wide CA trust store", "Yes (Magisk/KernelSU/APatch module + reboot)", "No", false),
        Row("IMEI / phone number / SIM serial", "Yes", "No (restricted since Android 10)", false),
        Row("Read SMS", "Yes", "Yes (READ_SMS permission)", true),
        Row("Device identifiers (Android ID)", "Yes", "Yes", true),
        Row("Install / clear / uninstall apps", "Yes", "No", false),
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_capability_table)
        findViewById<View>(R.id.btn_back).setOnClickListener { finish() }

        val table = findViewById<TableLayout>(R.id.capability_table)
        table.addView(headerRow())
        rows.forEach { table.addView(dataRow(it)) }
    }

    private fun cell(text: String, bold: Boolean = false, colorRes: Int? = null): TextView {
        return TextView(this).apply {
            this.text = text
            setPadding(dp(12), dp(10), dp(12), dp(10))
            textSize = 13f
            setTextColor(ContextCompat.getColor(this@CapabilityTableActivity, colorRes ?: R.color.cds_text_secondary))
            if (bold) setTypeface(typeface, Typeface.BOLD)
        }
    }

    private fun headerRow(): TableRow {
        return TableRow(this).apply {
            setBackgroundColor(ContextCompat.getColor(this@CapabilityTableActivity, R.color.cds_layer_01))
            addView(cell(getString(R.string.cap_col_capability), bold = true, colorRes = R.color.cds_text_primary))
            addView(cell(getString(R.string.cap_col_root), bold = true, colorRes = R.color.cds_text_primary))
            addView(cell(getString(R.string.cap_col_nonroot), bold = true, colorRes = R.color.cds_text_primary))
        }
    }

    private fun dataRow(row: Row): TableRow {
        return TableRow(this).apply {
            addView(cell(row.capability, colorRes = R.color.cds_text_primary))
            addView(cell(row.root, colorRes = R.color.cds_support_success))
            addView(cell(row.nonRoot, colorRes = if (row.nonRootOk) R.color.cds_support_success else R.color.cds_support_warning))
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
