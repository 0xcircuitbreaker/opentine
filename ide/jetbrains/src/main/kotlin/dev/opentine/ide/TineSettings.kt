package dev.opentine.ide

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.options.Configurable
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField

/** The `tine` executable and the per-call timeout. */
@State(name = "OpenTineSettings", storages = [Storage("opentine.xml")])
class TineSettings : PersistentStateComponent<TineSettings.Data> {
    data class Data(var tinePath: String = "tine", var timeoutSeconds: Long = 60)

    private var data = Data()

    override fun getState(): Data = data

    override fun loadState(state: Data) {
        data = state
    }

    companion object {
        fun get(): Data = ApplicationManager.getApplication().getService(TineSettings::class.java).state
    }
}

class TineSettingsConfigurable : Configurable {
    private val path = JTextField()

    override fun getDisplayName() = "OpenTine"

    override fun createComponent(): JComponent = JPanel().apply {
        add(JLabel("tine executable:"))
        add(path.apply { columns = 40; text = TineSettings.get().tinePath })
    }

    override fun isModified() = path.text != TineSettings.get().tinePath

    override fun apply() {
        TineSettings.get().tinePath = path.text.trim().ifEmpty { "tine" }
    }
}
