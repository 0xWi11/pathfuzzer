package pzfzr.gui;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.lang.ref.WeakReference;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.mozilla.universalchardet.UniversalDetector;

/**
 * Side-by-Side Response Diff Panel
 * 用于并排对比 Original Response 和 Modified Response 的差异
 */
public class ResponseDiffPanel extends JPanel {

    // UI 组件
    private JTextPane originalTextPane;
    private JTextPane modifiedTextPane;
    private JScrollPane originalScrollPane;
    private JScrollPane modifiedScrollPane;
    private JSplitPane splitPane;
    private JToggleButton diffToggleButton;

    // Diff 开关状态
    private boolean diffEnabled = true;

    // 数据引用（使用弱引用节省内存）
    private WeakReference<byte[]> originalResponseRef;
    private WeakReference<byte[]> modifiedResponseRef;

    // 自定义字体
    private Font customFont;

    // 颜色定义
    private static final Color COLOR_DELETED = new Color(255, 200, 200);  // 浅红色 - 删除内容
    private static final Color COLOR_INSERTED = new Color(200, 255, 200); // 浅绿色 - 新增内容
    private static final Color COLOR_EQUAL = Color.WHITE;                  // 白色 - 相同内容

    // 大小限制
    private static final int MAX_SIZE_BYTES = 1 * 1024 * 1024; // 1MB

    /**
     * 构造函数
     */
    public ResponseDiffPanel() {
        super(new BorderLayout());
        initializeFont();
        initializeUI();
    }

    /**
     * 初始化自定义字体
     */
    private void initializeFont() {
        try {
            // 尝试加载 Sarasa Gothic 字体
            String fontPath = "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Fonts\\SarasaGothicSC-Regular.ttf";
            java.io.File fontFile = new java.io.File(fontPath);

            if (fontFile.exists()) {
                Font baseFont = Font.createFont(Font.TRUETYPE_FONT, fontFile);
                customFont = baseFont.deriveFont(12f); // 12号字体
            } else {
                // 如果找不到自定义字体，使用系统等宽字体
                customFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);
            }
        } catch (Exception e) {
            // 字体加载失败，使用系统默认等宽字体
            customFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);
            System.err.println("[ResponseDiffPanel] 字体加载失败，使用默认字体: " + e.getMessage());
        }
    }

    /**
     * 初始化 UI 组件
     */
    private void initializeUI() {
        // 创建顶部工具栏
        JPanel toolbarPanel = createToolbar();

        // 创建左侧文本面板（Original Response）
        originalTextPane = createTextPane("Original Response");
        originalScrollPane = new JScrollPane(originalTextPane);
        originalScrollPane.setBorder(BorderFactory.createTitledBorder("Original Response"));

        // 创建右侧文本面板（Modified Response）
        modifiedTextPane = createTextPane("Modified Response");
        modifiedScrollPane = new JScrollPane(modifiedTextPane);
        modifiedScrollPane.setBorder(BorderFactory.createTitledBorder("Modified Response"));

        // 创建分割面板
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, originalScrollPane, modifiedScrollPane);
        splitPane.setResizeWeight(0.5); // 左右各占 50%
        splitPane.setDividerSize(5);

        // 同步滚动
        synchronizeScrolling();

        // 布局
        add(toolbarPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
    }

    /**
     * 创建工具栏
     */
    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        toolbar.setBackground(new Color(248, 249, 250));

        // Diff 开关按钮
        diffToggleButton = new JToggleButton("✓ Diff 已启用", true);
        diffToggleButton.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        diffToggleButton.setPreferredSize(new Dimension(110, 22));
        diffToggleButton.setFocusPainted(false);
        diffToggleButton.setToolTipText("切换 Diff 计算（关闭可提升性能）");

        // 设置按钮样式
        updateToggleButtonStyle();

        // 添加切换事件
        diffToggleButton.addActionListener(e -> {
            diffEnabled = diffToggleButton.isSelected();
            updateToggleButtonStyle();

            // 如果有缓存的响应数据，重新渲染
            if (originalResponseRef != null && modifiedResponseRef != null) {
                byte[] orig = originalResponseRef.get();
                byte[] modi = modifiedResponseRef.get();
                if (orig != null && modi != null) {
                    setResponses(orig, modi);
                }
            }
        });

        // 状态标签
        JLabel statusLabel = new JLabel("快速浏览模式：关闭 Diff 可提升性能");
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        statusLabel.setForeground(new Color(108, 117, 125));

        toolbar.add(diffToggleButton);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(statusLabel);

        return toolbar;
    }

    /**
     * 更新切换按钮样式
     */
    private void updateToggleButtonStyle() {
        if (diffEnabled) {
            diffToggleButton.setText("✓ Diff 已启用");
            diffToggleButton.setBackground(new Color(25, 135, 84)); // 绿色
            diffToggleButton.setForeground(Color.WHITE);
            diffToggleButton.setToolTipText("点击关闭 Diff（提升性能）");
        } else {
            diffToggleButton.setText("✗ Diff 已关闭");
            diffToggleButton.setBackground(new Color(220, 53, 69)); // 红色
            diffToggleButton.setForeground(Color.WHITE);
            diffToggleButton.setToolTipText("点击启用 Diff（显示差异）");
        }
    }

    /**
     * 创建文本面板
     */
    private JTextPane createTextPane(String name) {
        JTextPane textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setFont(customFont);
        textPane.setName(name);

        // 设置文本面板背景色
        textPane.setBackground(Color.WHITE);

        return textPane;
    }

    /**
     * 同步左右滚动条
     */
    private void synchronizeScrolling() {
        JScrollBar originalVertical = originalScrollPane.getVerticalScrollBar();
        JScrollBar modifiedVertical = modifiedScrollPane.getVerticalScrollBar();

        // 左侧滚动时同步右侧
        originalVertical.addAdjustmentListener(e -> {
            if (!e.getValueIsAdjusting()) {
                modifiedVertical.setValue(e.getValue());
            }
        });

        // 右侧滚动时同步左侧
        modifiedVertical.addAdjustmentListener(e -> {
            if (!e.getValueIsAdjusting()) {
                originalVertical.setValue(e.getValue());
            }
        });
    }

    /**
     * 设置要对比的响应数据（主入口方法）
     *
     * @param originalResponse 原始响应数据
     * @param modifiedResponse 修改后的响应数据
     */
    public void setResponses(byte[] originalResponse, byte[] modifiedResponse) {
        // 保存数据引用
        this.originalResponseRef = new WeakReference<>(originalResponse);
        this.modifiedResponseRef = new WeakReference<>(modifiedResponse);

        // 如果 Diff 被禁用，直接显示原始文本（快速模式）
        if (!diffEnabled) {
            displayRawResponses(originalResponse, modifiedResponse);
            return;
        }

        // 在后台线程计算 diff（启用 Diff 模式）
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            private String originalText;
            private String modifiedText;
            private boolean shouldContinue = true;

            @Override
            protected Void doInBackground() throws Exception {
                try {
                    // 检查空响应
                    if (originalResponse == null || originalResponse.length == 0) {
                        originalText = "响应为空";
                        modifiedText = modifiedResponse == null || modifiedResponse.length == 0 ?
                                "响应为空" : convertBytesToString(modifiedResponse);
                        return null;
                    }

                    if (modifiedResponse == null || modifiedResponse.length == 0) {
                        originalText = convertBytesToString(originalResponse);
                        modifiedText = "响应为空";
                        return null;
                    }

                    // 检查超大响应
                    if (originalResponse.length > MAX_SIZE_BYTES || modifiedResponse.length > MAX_SIZE_BYTES) {
                        int result = JOptionPane.showConfirmDialog(
                                ResponseDiffPanel.this,
                                String.format("响应数据较大（原始: %d KB, 修改后: %d KB）\n对比可能需要较长时间，是否继续？",
                                        originalResponse.length / 1024,
                                        modifiedResponse.length / 1024),
                                "警告",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.WARNING_MESSAGE
                        );

                        if (result != JOptionPane.YES_OPTION) {
                            shouldContinue = false;
                            return null;
                        }
                    }

                    // 转换为字符串
                    originalText = convertBytesToString(originalResponse);
                    modifiedText = convertBytesToString(modifiedResponse);

                    // 检查是否完全相同
                    if (originalText.equals(modifiedText)) {
                        originalText = "两个响应完全相同\n\n" + originalText;
                        modifiedText = "两个响应完全相同\n\n" + modifiedText;
                    }

                } catch (Exception e) {
                    System.err.println("[ResponseDiffPanel] 后台处理异常: " + e.getMessage());
                    e.printStackTrace();
                    originalText = "处理错误: " + e.getMessage();
                    modifiedText = "处理错误: " + e.getMessage();
                }

                return null;
            }

            @Override
            protected void done() {
                if (!shouldContinue) {
                    clear();
                    return;
                }

                // 在 EDT 线程更新 UI
                SwingUtilities.invokeLater(() -> {
                    try {
                        updateTextPanes(originalText, modifiedText);
                    } catch (Exception e) {
                        System.err.println("[ResponseDiffPanel] UI 更新异常: " + e.getMessage());
                        e.printStackTrace();
                    }
                });
            }
        };

        worker.execute();
    }

    /**
     * 快速模式：直接显示原始响应文本（不计算 Diff）
     */
    private void displayRawResponses(byte[] originalResponse, byte[] modifiedResponse) {
        SwingUtilities.invokeLater(() -> {
            try {
                // 转换为字符串
                String originalText = (originalResponse == null || originalResponse.length == 0) ?
                        "响应为空" : convertBytesToString(originalResponse);
                String modifiedText = (modifiedResponse == null || modifiedResponse.length == 0) ?
                        "响应为空" : convertBytesToString(modifiedResponse);

                // 直接显示原始文本（无高亮）
                originalTextPane.setText(originalText);
                modifiedTextPane.setText(modifiedText);

                // 滚动到顶部
                SwingUtilities.invokeLater(() -> {
                    originalTextPane.setCaretPosition(0);
                    modifiedTextPane.setCaretPosition(0);
                });

            } catch (Exception e) {
                System.err.println("[ResponseDiffPanel] 快速显示异常: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }

    /**
     * 更新文本面板内容
     */
    private void updateTextPanes(String originalText, String modifiedText) {
        try {
            // 计算 diff
            List<DiffLine> diffs = computeLineDiff(originalText, modifiedText);

            // 渲染左侧（Original）
            renderDiff(originalTextPane, diffs, true);

            // 渲染右侧（Modified）
            renderDiff(modifiedTextPane, diffs, false);

            // 滚动到顶部
            SwingUtilities.invokeLater(() -> {
                originalTextPane.setCaretPosition(0);
                modifiedTextPane.setCaretPosition(0);
            });

        } catch (Exception e) {
            System.err.println("[ResponseDiffPanel] 渲染异常: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 计算行级别的 diff
     *
     * @param original 原始文本
     * @param modified 修改后的文本
     * @return diff 结果列表
     */
    private List<DiffLine> computeLineDiff(String original, String modified) {
        List<DiffLine> result = new ArrayList<>();

        // 按行分割（保留换行符信息）
        String[] originalLines = splitLines(original);
        String[] modifiedLines = splitLines(modified);

        // 简单的逐行对比（可以替换为更复杂的 diff 算法）
        int maxLines = Math.max(originalLines.length, modifiedLines.length);

        for (int i = 0; i < maxLines; i++) {
            String origLine = i < originalLines.length ? originalLines[i] : null;
            String modiLine = i < modifiedLines.length ? modifiedLines[i] : null;

            DiffType type;
            if (origLine == null) {
                type = DiffType.INSERTED;
            } else if (modiLine == null) {
                type = DiffType.DELETED;
            } else if (origLine.equals(modiLine)) {
                type = DiffType.EQUAL;
            } else {
                type = DiffType.CHANGED;
            }

            result.add(new DiffLine(type, origLine, modiLine));
        }

        return result;
    }

    /**
     * 分割文本为行（保留空行）
     */
    private String[] splitLines(String text) {
        if (text == null || text.isEmpty()) {
            return new String[0];
        }

        // 使用正则表达式分割，保留换行符
        // 支持 \r\n 和 \n
        return text.split("(?<=\r\n)|(?<=\n)");
    }

    /**
     * 渲染 diff 结果到文本面板
     *
     * @param textPane 目标文本面板
     * @param diffs diff 结果列表
     * @param isOriginal 是否为原始响应（true=左侧，false=右侧）
     */
    private void renderDiff(JTextPane textPane, List<DiffLine> diffs, boolean isOriginal) {
        StyledDocument doc = textPane.getStyledDocument();

        try {
            // 清空文档
            doc.remove(0, doc.getLength());

            // 创建样式
            Style defaultStyle = textPane.addStyle("Default", null);
            StyleConstants.setFontFamily(defaultStyle, customFont.getFamily());
            StyleConstants.setFontSize(defaultStyle, customFont.getSize());

            Style deletedStyle = textPane.addStyle("Deleted", defaultStyle);
            StyleConstants.setBackground(deletedStyle, COLOR_DELETED);

            Style insertedStyle = textPane.addStyle("Inserted", defaultStyle);
            StyleConstants.setBackground(insertedStyle, COLOR_INSERTED);

            Style changedStyle = textPane.addStyle("Changed", defaultStyle);
            StyleConstants.setBackground(changedStyle,
                    isOriginal ? COLOR_DELETED : COLOR_INSERTED);

            // 逐行渲染
            for (DiffLine diff : diffs) {
                String line = isOriginal ? diff.originalLine : diff.modifiedLine;

                if (line == null) {
                    // 对方有这行，本侧没有，显示空行占位
                    line = "\n";
                    doc.insertString(doc.getLength(), line, defaultStyle);
                    continue;
                }

                Style style;
                switch (diff.type) {
                    case DELETED:
                        style = isOriginal ? deletedStyle : defaultStyle;
                        break;
                    case INSERTED:
                        style = isOriginal ? defaultStyle : insertedStyle;
                        break;
                    case CHANGED:
                        style = changedStyle;
                        break;
                    default:
                        style = defaultStyle;
                }

                doc.insertString(doc.getLength(), line, style);
            }

        } catch (BadLocationException e) {
            System.err.println("[ResponseDiffPanel] 文档渲染异常: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 字节数组转字符串（自动检测编码）
     */
    private String convertBytesToString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        try {
            // 使用 universalchardet 检测编码
            String encoding = detectEncoding(bytes);

            if (encoding != null) {
                return new String(bytes, Charset.forName(encoding));
            }

            // 如果检测失败，尝试常用编码
            String[] encodings = {"UTF-8", "GBK", "GB2312", "ISO-8859-1"};

            for (String enc : encodings) {
                try {
                    String result = new String(bytes, Charset.forName(enc));
                    // 简单验证：如果没有太多乱码字符，就使用这个编码
                    if (isValidText(result)) {
                        return result;
                    }
                } catch (Exception e) {
                    // 继续尝试下一个编码
                }
            }

            // 最后使用 UTF-8
            return new String(bytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            System.err.println("[ResponseDiffPanel] 编码转换异常: " + e.getMessage());
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    /**
     * 检测字节数组的编码
     */
    private String detectEncoding(byte[] bytes) {
        try {
            UniversalDetector detector = new UniversalDetector(null);

            // 只检测前面部分数据以提高速度
            int detectSize = Math.min(bytes.length, 4096);
            detector.handleData(bytes, 0, detectSize);
            detector.dataEnd();

            String encoding = detector.getDetectedCharset();
            detector.reset();

            return encoding;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 验证文本是否有效（简单检查是否有过多乱码）
     */
    private boolean isValidText(String text) {
        if (text == null || text.isEmpty()) {
            return true;
        }

        int replacementCount = 0;
        for (char c : text.toCharArray()) {
            if (c == '\uFFFD') { // Unicode 替换字符
                replacementCount++;
            }
        }

        // 如果替换字符超过 5%，认为编码可能不正确
        return replacementCount < text.length() * 0.05;
    }

    /**
     * 清除当前显示的内容，释放资源
     */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            originalTextPane.setText("");
            modifiedTextPane.setText("");

            if (originalResponseRef != null) {
                originalResponseRef.clear();
            }
            if (modifiedResponseRef != null) {
                modifiedResponseRef.clear();
            }
        });
    }

    /**
     * Diff 行数据结构
     */
    private static class DiffLine {
        final DiffType type;
        final String originalLine;
        final String modifiedLine;

        DiffLine(DiffType type, String originalLine, String modifiedLine) {
            this.type = type;
            this.originalLine = originalLine;
            this.modifiedLine = modifiedLine;
        }
    }

    /**
     * Diff 类型枚举
     */
    private enum DiffType {
        EQUAL,      // 相同
        DELETED,    // 删除（仅在原始中存在）
        INSERTED,   // 插入（仅在修改后存在）
        CHANGED     // 修改（两边都存在但内容不同）
    }
}