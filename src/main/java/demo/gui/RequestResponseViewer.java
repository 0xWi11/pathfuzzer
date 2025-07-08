package demo.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import demo.model.OriginalRequestResponse;
import demo.model.ModifiedRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.KeyEvent;
import java.lang.ref.WeakReference;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class RequestResponseViewer extends JSplitPane {
    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;
    private final HttpRequestEditor originalRequestViewer;
    private final HttpResponseEditor originalResponseViewer;
    private final JButton previousButton;
    private final JButton nextButton;
    private HistoryPanel historyPanel;
    // Add weak references to current data
    private WeakReference<OriginalRequestResponse> currentOriginal;
    private WeakReference<ModifiedRequestResponse> currentModified;

    public RequestResponseViewer(MontoyaApi api) {
        super(JSplitPane.VERTICAL_SPLIT);

        // 创建导航按钮
        previousButton = new JButton("▲ Previous");
        nextButton = new JButton("▼ Next");

        // 使用 BoxLayout 创建垂直布局的导航面板
        JPanel navigationPanel = new JPanel();
        navigationPanel.setLayout(new BoxLayout(navigationPanel, BoxLayout.Y_AXIS));

        // 添加一些垂直间距
        navigationPanel.add(Box.createVerticalStrut(0));
        navigationPanel.add(previousButton);
        navigationPanel.add(Box.createVerticalStrut(0));
        navigationPanel.add(nextButton);
        navigationPanel.add(Box.createVerticalStrut(0));

        // 设置按钮的首选大小以保持一致的宽度
        Dimension buttonSize = new Dimension(200, 22);
        previousButton.setPreferredSize(buttonSize);
        nextButton.setPreferredSize(buttonSize);
        previousButton.setMaximumSize(buttonSize);
        nextButton.setMaximumSize(buttonSize);

        // 设置按钮的默认和悬停颜色
        Color defaultColor = new Color(238, 238, 238);  // 默认浅灰色
        Color hoverColor = new Color(200, 200, 200);    // 悬停时的深灰色

        previousButton.setBackground(defaultColor);
        nextButton.setBackground(defaultColor);

        // 为按钮添加鼠标监听器
        MouseAdapter buttonHoverListener = new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                ((JButton)e.getSource()).setBackground(hoverColor);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                ((JButton)e.getSource()).setBackground(defaultColor);
            }
        };

        previousButton.addMouseListener(buttonHoverListener);
        nextButton.addMouseListener(buttonHoverListener);

        // 确保按钮会显示背景色
        previousButton.setContentAreaFilled(true);
        nextButton.setContentAreaFilled(true);

        // 添加快捷键支持
        // 为Previous按钮添加Ctrl+Shift+Z快捷键
        String previousActionKey = "previousAction";
        Action previousAction = new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                if (historyPanel != null && historyPanel.hasPrevious()) {
                    historyPanel.selectPrevious();
                }
            }
        };

        // 为Next按钮添加Ctrl+Shift+X快捷键
        String nextActionKey = "nextAction";
        Action nextAction = new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                if (historyPanel != null && historyPanel.hasNext()) {
                    historyPanel.selectNext();
                }
            }
        };

        // 设置快捷键
        KeyStroke previousKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK);
        KeyStroke nextKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_X, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK);

        // 更新按钮的工具提示文本，显示快捷键信息
        previousButton.setToolTipText("Previous (Ctrl+Shift+Z)");
        nextButton.setToolTipText("Next (Ctrl+Shift+X)");

        // 将快捷键绑定到面板的InputMap和ActionMap
        navigationPanel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(previousKeyStroke, previousActionKey);
        navigationPanel.getActionMap().put(previousActionKey, previousAction);
        navigationPanel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(nextKeyStroke, nextActionKey);
        navigationPanel.getActionMap().put(nextActionKey, nextAction);

        // 使按钮在水平方向上居中
        previousButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        nextButton.setAlignmentX(Component.CENTER_ALIGNMENT);

        // 创建上部面板（原始请求/响应）
        JPanel upperPanel = new JPanel(new BorderLayout());
        JTabbedPane upperTabs = new JTabbedPane();

        originalRequestViewer = api.userInterface().createHttpRequestEditor(READ_ONLY);
        JPanel originalRequestTab = new JPanel(new BorderLayout());
        originalRequestTab.add(originalRequestViewer.uiComponent(), BorderLayout.CENTER);

        originalResponseViewer = api.userInterface().createHttpResponseEditor(READ_ONLY);
        JPanel originalResponseTab = new JPanel(new BorderLayout());
        originalResponseTab.add(originalResponseViewer.uiComponent(), BorderLayout.CENTER);

        upperTabs.addTab("Original Request", originalRequestTab);
        upperTabs.addTab("Original Response", originalResponseTab);
        upperPanel.add(upperTabs, BorderLayout.CENTER);

        // 创建包含导航按钮的中间面板
        JPanel middlePanel = new JPanel(new BorderLayout());
        middlePanel.add(navigationPanel, BorderLayout.CENTER);

        // 创建包含所有组件的主面板
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(upperPanel, BorderLayout.CENTER);
        mainPanel.add(middlePanel, BorderLayout.SOUTH);

        // 创建下部面板（修改后的请求/响应）
        JPanel lowerPanel = new JPanel(new BorderLayout());
        JTabbedPane lowerTabs = new JTabbedPane();

        requestViewer = api.userInterface().createHttpRequestEditor(READ_ONLY);
        JPanel modifiedRequestTab = new JPanel(new BorderLayout());
        modifiedRequestTab.add(requestViewer.uiComponent(), BorderLayout.CENTER);

        responseViewer = api.userInterface().createHttpResponseEditor(READ_ONLY);
        JPanel modifiedResponseTab = new JPanel(new BorderLayout());
        modifiedResponseTab.add(responseViewer.uiComponent(), BorderLayout.CENTER);

        lowerTabs.addTab("Modified Request", modifiedRequestTab);
        lowerTabs.addTab("Modified Response", modifiedResponseTab);
        lowerPanel.add(lowerTabs, BorderLayout.CENTER);

        setTopComponent(mainPanel);
        setBottomComponent(lowerPanel);
        setResizeWeight(0.5);

        // 设置按钮状态
        updateButtonState();
    }

    public void setHistoryPanel(HistoryPanel historyPanel) {
        this.historyPanel = historyPanel;

        // 设置按钮监听器
        previousButton.addActionListener(e -> historyPanel.selectPrevious());
        nextButton.addActionListener(e -> historyPanel.selectNext());
    }

    public void updateViewers(OriginalRequestResponse original, ModifiedRequestResponse modified) {
        // Clear previous data first
        clearViewers();

        if (original != null && modified != null) {
            // Store weak references
            currentOriginal = new WeakReference<>(original);
            currentModified = new WeakReference<>(modified);

            // Update viewers with new data
            SwingUtilities.invokeLater(() -> {
                try {
                    originalRequestViewer.setRequest(original.getOriginalRequest());
                    originalResponseViewer.setResponse(original.getOriginalResponse());
                    requestViewer.setRequest(modified.getModifiedRequest());
                    responseViewer.setResponse(modified.getModifiedResponse());
                } catch (Exception e) {
                    // Handle potential exceptions during viewer updates
                    e.printStackTrace();
                }
            });
        }
        updateButtonState();
    }

    private void updateButtonState() {
        if (historyPanel != null) {
            previousButton.setEnabled(historyPanel.hasPrevious());
            nextButton.setEnabled(historyPanel.hasNext());
        }
    }
    private void clearViewers() {
        SwingUtilities.invokeLater(() -> {
            try {
                // Clear all viewers
                originalRequestViewer.setRequest(null);
                originalResponseViewer.setResponse(null);
                requestViewer.setRequest(null);
                responseViewer.setResponse(null);

                // Clear references
                if (currentOriginal != null) {
                    currentOriginal.clear();
                }
                if (currentModified != null) {
                    currentModified.clear();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
    // Add cleanup method
    public void cleanup() {
        clearViewers();
        // Remove listeners
        previousButton.removeActionListener(l -> {});
        nextButton.removeActionListener(l -> {});
        historyPanel = null;
    }
}