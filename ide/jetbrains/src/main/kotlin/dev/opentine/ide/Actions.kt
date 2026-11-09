package dev.opentine.ide

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.editor.TextAnnotationGutterProvider
import com.intellij.openapi.editor.colors.ColorKey
import com.intellij.openapi.editor.colors.EditorFontType
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.guessProjectDir
import com.intellij.openapi.vfs.VirtualFile
import dev.opentine.ide.core.BlameRecord
import dev.opentine.ide.core.Explain
import dev.opentine.ide.core.Provenance
import dev.opentine.ide.core.TineCli
import dev.opentine.ide.core.Verdict
import java.awt.Color
import java.io.File
import java.nio.file.Path

private fun cli(): TineCli = TineSettings.get().let { TineCli(listOf(it.tinePath), it.timeoutSeconds) }

private fun notify(project: Project?, text: String, type: NotificationType) {
    NotificationGroupManager.getInstance().getNotificationGroup("OpenTine").createNotification(text, type).notify(project)
}

/** The work tree (the project's base directory) and the file's repository-relative path. */
private fun locate(project: Project, file: VirtualFile): Pair<File, String> {
    val root = project.guessProjectDir() ?: error("the project has no base directory")
    val base = Path.of(root.path)
    return base.toFile() to TineCli.repoRelative(base, Path.of(file.path))
}

/** The AI-blame gutter: one label per AI-written line, from `tine blame FILE --lines --json`. */
private class AiBlameGutter(private val record: BlameRecord) : TextAnnotationGutterProvider {
    override fun getLineText(line: Int, editor: Editor): String? = record.gutterLabel(line)

    override fun getToolTip(line: Int, editor: Editor): String? = record.tooltip(line)

    override fun getStyle(line: Int, editor: Editor): EditorFontType = EditorFontType.ITALIC

    override fun getColor(line: Int, editor: Editor): ColorKey? = null

    override fun getBgColor(line: Int, editor: Editor): Color? = null

    override fun getPopupActions(line: Int, editor: Editor) = emptyList<AnAction>()

    override fun gutterClosed() {}
}

class ToggleAiBlameAction : AnAction() {
    override fun getActionUpdateThread() = ActionUpdateThread.BGT

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val editor = event.getData(CommonDataKeys.EDITOR) ?: return
        val file = event.getData(CommonDataKeys.VIRTUAL_FILE) ?: return
        if (editor.gutter.isAnnotationsShown) {
            editor.gutter.closeAllAnnotations()
            return
        }
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val (root, path) = locate(project, file)
                val record = BlameRecord.parse(cli().json(TineCli.blameArgs(path), root))
                ApplicationManager.getApplication().invokeLater {
                    editor.gutter.registerTextAnnotation(AiBlameGutter(record))
                    notify(project, "OpenTine: ${record.aiShare()}", NotificationType.INFORMATION)
                }
            } catch (e: Exception) {
                notify(project, "OpenTine: ${e.message}", NotificationType.WARNING)
            }
        }
    }
}

class VerifyLineAction : AnAction() {
    override fun getActionUpdateThread() = ActionUpdateThread.BGT

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val editor = event.getData(CommonDataKeys.EDITOR) ?: return
        val file = event.getData(CommonDataKeys.VIRTUAL_FILE) ?: return
        val line = editor.caretModel.logicalPosition.line + 1
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val (root, path) = locate(project, file)
                val tine = cli()
                val provenance = Provenance.parse(tine.json(TineCli.whyArgs(path, line), root))
                val verdict = if (provenance.run.isEmpty()) null else try {
                    Verdict.parse(tine.json(TineCli.verifyArgs(provenance.run), root))
                } catch (e: Exception) {
                    null // the run is not held in this repository
                }
                val type = if (verdict != null && !verdict.ok) NotificationType.ERROR else NotificationType.INFORMATION
                notify(project, Explain.line(provenance, verdict), type)
            } catch (e: Exception) {
                notify(project, "OpenTine: ${e.message}", NotificationType.WARNING)
            }
        }
    }
}
