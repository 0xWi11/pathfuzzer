package pzfzr.gui;

import burp.api.montoya.http.message.responses.HttpResponse;
import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Side-by-Side 响应对比面板
 * 用于对比 Original Response 和 Modified Response 的差异
 */
public class ResponseDiffPanel extends JPanel {
    // UI 组件
    private final JTextPane originalTextPane;
    private final JTextPane modifiedTextPane;
    private final JScrollPane originalScrollPane;
    private final JScrollPane modifiedScrollPane;
    private final JPanel lineNumberPanelOriginal;
    private final JPanel lineNumberPanelModified;

    // 数据存储（使用弱引用）
    private WeakReference<String> originalText;
    private WeakReference<String> modifiedText;

    // 线程池（用于后台计算diff）
    private final ExecutorService diffExecutor;

    // 字体配置
    private static final String FONT_PATH = "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Fonts\\SarasaGothicSC-Regular.ttf";
    private Font monoFont;

    // 差异高亮颜色
    private static final Color COLOR_ADDED = new Color(200, 255, 200);      // 淡绿色 - 新增行
    private static final Color COLOR_DELETED = new Color(255, 200, 200);    // 淡红色 - 删除行
    private static final Color COLOR_MODIFIED = new Color(255, 255, 200);   // 淡黄色 - 修改行
    private static final Color COLOR_LINE_NUMBER_BG = new Color(240, 240, 240);

    // 最大响应大小（1MB）
    private static final int MAX_RESPONSE_SIZE = 1024 * 1024;

    public ResponseDiffPanel() {
        super(new BorderLayout());

        // 初始化线程池
        diffExecutor = Executors.newSingleThreadExecutor();

        // 加载字体
        loadCustomFont();

        // 创建文本面板
        originalTextPane = createTextPane();
        modifiedTextPane = createTextPane();

        // 创建行号面板
        lineNumberPanelOriginal = new JPanel();
        lineNumberPanelModified = new JPanel();

        // 创建滚动面板
        originalScrollPane = createScrollPane(originalTextPane, lineNumberPanelOriginal, "Original Response");
        modifiedScrollPane = createScrollPane(modifiedTextPane, lineNumberPanelModified, "Modified Response");

        // 同步滚动
        synchronizeScrolling();

        // 创建分割面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                originalScrollPane,
                modifiedScrollPane);
        splitPane.setDividerLocation(0.5);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerSize(8);

        add(splitPane, BorderLayout.CENTER);
    }

    /**
     * 加载自定义等宽字体
     */
    private void loadCustomFont() {
        try {
            File fontFile = new File(FONT_PATH);
            if (fontFile.exists()) {
                Font baseFont = Font.createFont(Font.TRUETYPE_FONT, fontFile);
                monoFont = baseFont.deriveFont(Font.PLAIN, 12f);
                System.out.println("[ResponseDiffPanel] 成功加载自定义字体: " + FONT_PATH);
            } else {
                // 回退到系统等宽字体
                monoFont = new Font("Monospaced", Font.PLAIN, 12);
                System.out.println("[ResponseDiffPanel] 字体文件不存在，使用系统等宽字体");
            }
        } catch (Exception e) {
            monoFont = new Font("Monospaced", Font.PLAIN, 12);
            System.err.println("[ResponseDiffPanel] 字体加载失败: " + e.getMessage());
        }
    }

    /**
     * 创建文本面板
     */
    private JTextPane createTextPane() {
        JTextPane textPane = new JTextPane();
        textPane.setFont(monoFont);
        textPane.setEditable(false);
        textPane.setBackground(Color.WHITE);
        return textPane;
    }

    /**
     * 创建滚动面板（带行号）
     */
    private JScrollPane createScrollPane(JTextPane textPane, JPanel lineNumberPanel, String title) {
        JScrollPane scrollPane = new JScrollPane(textPane);
        scrollPane.setBorder(BorderFactory.createTitledBorder(title));

        // 设置行号面板
        lineNumberPanel.setLayout(new BorderLayout());
        lineNumberPanel.setBackground(COLOR_LINE_NUMBER_BG);
        lineNumberPanel.setPreferredSize(new Dimension(40, 0));

        scrollPane.setRowHeaderView(lineNumberPanel);

        return scrollPane;
    }

    /**
     * 同步两个滚动面板的滚动
     */
    private void synchronizeScrolling() {
        JScrollBar originalScrollBar = originalScrollPane.getVerticalScrollBar();
        JScrollBar modifiedScrollBar = modifiedScrollPane.getVerticalScrollBar();

        // Original -> Modified
        originalScrollBar.addAdjustmentListener(e -> {
            if (!e.getValueIsAdjusting()) {
                modifiedScrollBar.setValue(e.getValue());
            }
        });

        // Modified -> Original
        modifiedScrollBar.addAdjustmentListener(e -> {
            if (!e.getValueIsAdjusting()) {
                originalScrollBar.setValue(e.getValue());
            }
        });

        // 同步水平滚动
        JScrollBar originalHScrollBar = originalScrollPane.getHorizontalScrollBar();
        JScrollBar modifiedHScrollBar = modifiedScrollPane.getHorizontalScrollBar();

        originalHScrollBar.addAdjustmentListener(e -> {
            if (!e.getValueIsAdjusting()) {
                modifiedHScrollBar.setValue(e.getValue());
            }
        });

        modifiedHScrollBar.addAdjustmentListener(e -> {
            if (!e.getValueIsAdjusting()) {
                originalHScrollBar.setValue(e.getValue());
            }
        });
    }

    /**
     * 更新对比视图
     * @param originalResponse 原始响应
     * @param modifiedResponse 修改后的响应
     */
    public void updateDiff(HttpResponse originalResponse, HttpResponse modifiedResponse) {
        // 在EDT线程中清空显示
        SwingUtilities.invokeLater(() -> {
            originalTextPane.setText("正在加载...");
            modifiedTextPane.setText("正在加载...");
        });

        // 在后台线程中处理响应
        diffExecutor.submit(() -> {
            try {
                // 检查空响应
                if (originalResponse == null || modifiedResponse == null) {
                    showMessage("响应为空", "响应为空");
                    return;
                }

                // 获取响应字节
                byte[] originalBytes = originalResponse.toByteArray().getBytes();
                byte[] modifiedBytes = modifiedResponse.toByteArray().getBytes();

                // 检查超大响应
                if (originalBytes.length > MAX_RESPONSE_SIZE || modifiedBytes.length > MAX_RESPONSE_SIZE) {
                    int result = JOptionPane.showConfirmDialog(
                            ResponseDiffPanel.this,
                            String.format("响应大小超过1MB (原始: %d bytes, 修改: %d bytes)\n是否继续加载?",
                                    originalBytes.length, modifiedBytes.length),
                            "警告",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE
                    );

                    if (result != JOptionPane.YES_OPTION) {
                        showMessage("用户取消", "用户取消");
                        return;
                    }
                }

                // 检测编码并转换为文本
                String originalStr = decodeBytes(originalBytes);
                String modifiedStr = decodeBytes(modifiedBytes);

                // 存储到弱引用
                originalText = new WeakReference<>(originalStr);
                modifiedText = new WeakReference<>(modifiedStr);

                // 检查是否完全相同
                if (originalStr.equals(modifiedStr)) {
                    showMessage("两个响应完全相同", "两个响应完全相同");
                    return;
                }

                // 计算差异
                List<DiffLine> diff = computeDiff(originalStr, modifiedStr);

                // 在EDT线程中更新UI
                SwingUtilities.invokeLater(() -> displayDiff(diff, originalStr, modifiedStr));

            } catch (Exception e) {
                e.printStackTrace();
                SwingUtilities.invokeLater(() -> {
                    showMessage("错误: " + e.getMessage(), "错误: " + e.getMessage());
                });
            }
        });
    }

    /**
     * 自动检测编码并解码字节
     */
    private String decodeBytes(byte[] bytes) {
        // 尝试多种编码
        Charset[] charsets = {
                StandardCharsets.UTF_8,
                Charset.forName("GBK"),
                Charset.forName("GB2312"),
                StandardCharsets.ISO_8859_1
        };

        // 优先尝试UTF-8
        try {
            String utf8Str = new String(bytes, StandardCharsets.UTF_8);
            // 简单验证：检查是否包含替换字符
            if (!utf8Str.contains("\uFFFD")) {
                return utf8Str;
            }
        } catch (Exception e) {
            // 继续尝试其他编码
        }

        // 尝试其他编码
        for (Charset charset : charsets) {
            try {
                String decoded = new String(bytes, charset);
                if (!decoded.contains("\uFFFD")) {
                    System.out.println("[ResponseDiffPanel] 使用编码: " + charset.name());
                    return decoded;
                }
            } catch (Exception e) {
                // 继续尝试下一个
            }
        }

        // 回退到UTF-8
        System.out.println("[ResponseDiffPanel] 回退到UTF-8编码");
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * 计算两个文本的差异（逐行对比）
     */
    private List<DiffLine> computeDiff(String original, String modified) {
        String[] originalLines = splitLines(original);
        String[] modifiedLines = splitLines(modified);

        List<DiffLine> result = new ArrayList<>();

        // 使用简单的逐行对比算法
        int maxLines = Math.max(originalLines.length, modifiedLines.length);

        for (int i = 0; i < maxLines; i++) {
            String origLine = i < originalLines.length ? originalLines[i] : null;
            String modLine = i < modifiedLines.length ? modifiedLines[i] : null;

            if (origLine == null) {
                // 修改后新增的行
                result.add(new DiffLine(null, modLine, DiffType.ADDED));
            } else if (modLine == null) {
                // 原始中有但修改后删除的行
                result.add(new DiffLine(origLine, null, DiffType.DELETED));
            } else if (origLine.equals(modLine)) {
                // 相同行
                result.add(new DiffLine(origLine, modLine, DiffType.UNCHANGED));
            } else {
                // 修改的行
                result.add(new DiffLine(origLine, modLine, DiffType.MODIFIED));
            }
        }

        return result;
    }

    /**
     * 按行分割文本（保留原始换行符）
     */
    private String[] splitLines(String text) {
        if (text == null || text.isEmpty()) {
            return new String[0];
        }

        // 保留空行，不使用正则表达式分割以保留换行符类型
        List<String> lines = new ArrayList<>();
        StringBuilder line = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (c == '\r') {
                // 检查是否是\r\n
                if (i + 1 < text.length() && text.charAt(i + 1) == '\n') {
                    lines.add(line.toString());
                    line.setLength(0);
                    i++; // 跳过\n
                } else {
                    // 单独的\r
                    lines.add(line.toString());
                    line.setLength(0);
                }
            } else if (c == '\n') {
                // 单独的\n
                lines.add(line.toString());
                line.setLength(0);
            } else {
                line.append(c);
            }
        }

        // 添加最后一行（如果有）
        if (line.length() > 0) {
            lines.add(line.toString());
        }

        return lines.toArray(new String[0]);
    }

    /**
     * 显示差异结果
     */
    private void displayDiff(List<DiffLine> diff, String originalFull, String modifiedFull) {
        try {
            // 清空文本
            originalTextPane.setText("");
            modifiedTextPane.setText("");

            StyledDocument originalDoc = originalTextPane.getStyledDocument();
            StyledDocument modifiedDoc = modifiedTextPane.getStyledDocument();

            // 创建样式
            Style defaultStyle = originalTextPane.addStyle("default", null);
            StyleConstants.setFontFamily(defaultStyle, monoFont.getFamily());
            StyleConstants.setFontSize(defaultStyle, monoFont.getSize());

            Style addedStyle = originalTextPane.addStyle("added", defaultStyle);
            StyleConstants.setBackground(addedStyle, COLOR_ADDED);

            Style deletedStyle = originalTextPane.addStyle("deleted", defaultStyle);
            StyleConstants.setBackground(deletedStyle, COLOR_DELETED);

            Style modifiedStyle = originalTextPane.addStyle("modified", defaultStyle);
            StyleConstants.setBackground(modifiedStyle, COLOR_MODIFIED);

            // 逐行添加文本和高亮
            int originalLineNum = 1;
            int modifiedLineNum = 1;

            for (DiffLine diffLine : diff) {
                Style origStyle = defaultStyle;
                Style modStyle = defaultStyle;

                switch (diffLine.type) {
                    case ADDED:
                        modStyle = addedStyle;
                        break;
                    case DELETED:
                        origStyle = deletedStyle;
                        break;
                    case MODIFIED:
                        origStyle = modifiedStyle;
                        modStyle = modifiedStyle;
                        break;
                }

                // 添加原始行
                if (diffLine.originalLine != null) {
                    originalDoc.insertString(originalDoc.getLength(),
                            diffLine.originalLine + "\n", origStyle);
                    originalLineNum++;
                } else {
                    originalDoc.insertString(originalDoc.getLength(), "\n", origStyle);
                    originalLineNum++;
                }

                // 添加修改后的行
                if (diffLine.modifiedLine != null) {
                    modifiedDoc.insertString(modifiedDoc.getLength(),
                            diffLine.modifiedLine + "\n", modStyle);
                    modifiedLineNum++;
                } else {
                    modifiedDoc.insertString(modifiedDoc.getLength(), "\n", modStyle);
                    modifiedLineNum++;
                }
            }

            // 更新行号
            updateLineNumbers(lineNumberPanelOriginal, originalLineNum - 1);
            updateLineNumbers(lineNumberPanelModified, modifiedLineNum - 1);

            // 滚动到顶部
            originalTextPane.setCaretPosition(0);
            modifiedTextPane.setCaretPosition(0);

        } catch (BadLocationException e) {
            e.printStackTrace();
            showMessage("显示错误", "显示错误");
        }
    }

    /**
     * 更新行号显示
     */
    private void updateLineNumbers(JPanel lineNumberPanel, int lineCount) {
        lineNumberPanel.removeAll();

        JTextArea lineNumberArea = new JTextArea();
        lineNumberArea.setFont(monoFont);
        lineNumberArea.setBackground(COLOR_LINE_NUMBER_BG);
        lineNumberArea.setForeground(Color.GRAY);
        lineNumberArea.setEditable(false);

        StringBuilder lineNumbers = new StringBuilder();
        for (int i = 1; i <= lineCount; i++) {
            lineNumbers.append(i).append("\n");
        }

        lineNumberArea.setText(lineNumbers.toString());
        lineNumberPanel.add(lineNumberArea, BorderLayout.CENTER);
        lineNumberPanel.revalidate();
        lineNumberPanel.repaint();
    }

    /**
     * 显示提示消息
     */
    private void showMessage(String originalMsg, String modifiedMsg) {
        SwingUtilities.invokeLater(() -> {
            originalTextPane.setText(originalMsg);
            modifiedTextPane.setText(modifiedMsg);
            lineNumberPanelOriginal.removeAll();
            lineNumberPanelModified.removeAll();
            lineNumberPanelOriginal.revalidate();
            lineNumberPanelModified.revalidate();
        });
    }

    /**
     * 清空资源
     */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            originalTextPane.setText("");
            modifiedTextPane.setText("");
            lineNumberPanelOriginal.removeAll();
            lineNumberPanelModified.removeAll();

            if (originalText != null) {
                originalText.clear();
            }
            if (modifiedText != null) {
                modifiedText.clear();
            }

            System.gc(); // 建议垃圾回收
        });
    }

    /**
     * 关闭面板时清理资源
     */
    public void cleanup() {
        clear();
        diffExecutor.shutdown();
    }

    // ===== 内部类 =====

    /**
     * 差异行数据结构
     */
    private static class DiffLine {
        String originalLine;
        String modifiedLine;
        DiffType type;

        DiffLine(String originalLine, String modifiedLine, DiffType type) {
            this.originalLine = originalLine;
            this.modifiedLine = modifiedLine;
            this.type = type;
        }
    }

    /**
     * 差异类型枚举
     */
    private enum DiffType {
        UNCHANGED,  // 未改变
        ADDED,      // 新增
        DELETED,    // 删除
        MODIFIED    // 修改
    }
}