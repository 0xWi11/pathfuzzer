package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import pzfzr.model.OriginalRequestResponse;
import pzfzr.model.ModifiedRequestResponse;

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
    // 添加对当前数据的弱引用
    private WeakReference<OriginalRequestResponse> currentOriginal;
    private WeakReference<ModifiedRequestResponse> currentModified;

    public RequestResponseViewer(MontoyaApi api) {
        super(JSplitPane.HORIZONTAL_SPLIT); // 修改：改为水平分割（左右结构）

        // 创建导航按钮（保持功能，但暂时隐藏）
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

        // 暂时隐藏导航面板
        navigationPanel.setVisible(false);

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

        // 创建左侧面板（请求 - 原始和修改后）
        JPanel leftPanel = new JPanel(new BorderLayout());
        JTabbedPane leftTabs = new JTabbedPane();

        originalRequestViewer = api.userInterface().createHttpRequestEditor(READ_ONLY);
        JPanel originalRequestTab = new JPanel(new BorderLayout());
        originalRequestTab.add(originalRequestViewer.uiComponent(), BorderLayout.CENTER);

        requestViewer = api.userInterface().createHttpRequestEditor(READ_ONLY);
        JPanel modifiedRequestTab = new JPanel(new BorderLayout());
        modifiedRequestTab.add(requestViewer.uiComponent(), BorderLayout.CENTER);

        leftTabs.addTab("Original Request", originalRequestTab);
        leftTabs.addTab("Modified Request", modifiedRequestTab);
        leftPanel.add(leftTabs, BorderLayout.CENTER);

        // 可选择性地将导航面板添加到左侧面板的底部（暂时隐藏）
        leftPanel.add(navigationPanel, BorderLayout.SOUTH);

        // 创建右侧面板（响应 - 原始和修改后）
        JPanel rightPanel = new JPanel(new BorderLayout());
        JTabbedPane rightTabs = new JTabbedPane();

        originalResponseViewer = api.userInterface().createHttpResponseEditor(READ_ONLY);
        JPanel originalResponseTab = new JPanel(new BorderLayout());
        originalResponseTab.add(originalResponseViewer.uiComponent(), BorderLayout.CENTER);

        responseViewer = api.userInterface().createHttpResponseEditor(READ_ONLY);
        JPanel modifiedResponseTab = new JPanel(new BorderLayout());
        modifiedResponseTab.add(responseViewer.uiComponent(), BorderLayout.CENTER);

        rightTabs.addTab("Original Response", originalResponseTab);
        rightTabs.addTab("Modified Response", modifiedResponseTab);
        rightPanel.add(rightTabs, BorderLayout.CENTER);

        // 设置左右组件
        setLeftComponent(leftPanel);
        setRightComponent(rightPanel);
        setResizeWeight(0.5); // 左右各占一半

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
        // 首先清除之前的数据
        clearViewers();

        if (original != null && modified != null) {
            // 存储弱引用
            currentOriginal = new WeakReference<>(original);
            currentModified = new WeakReference<>(modified);

            // 使用新数据更新查看器
            SwingUtilities.invokeLater(() -> {
                try {
                    originalRequestViewer.setRequest(original.getOriginalRequest());
                    originalResponseViewer.setResponse(original.getOriginalResponse());
                    requestViewer.setRequest(modified.getModifiedRequest());
                    requestViewer.setSearchExpression(modified.getExpression());
                    responseViewer.setResponse(modified.getModifiedResponse());
                } catch (Exception e) {
                    // 处理查看器更新期间的潜在异常
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
                // 清除所有查看器
                originalRequestViewer.setRequest(null);
                originalResponseViewer.setResponse(null);
                requestViewer.setRequest(null);
                responseViewer.setResponse(null);

                // 清除引用
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

    // 添加清理方法
    public void cleanup() {
        clearViewers();
        // 移除监听器
        previousButton.removeActionListener(l -> {});
        nextButton.removeActionListener(l -> {});
        historyPanel = null;
    }

    // 添加显示/隐藏导航按钮的方法（以备将来使用）
    public void setNavigationVisible(boolean visible) {
        // 找到导航面板并设置可见性
        Component leftComponent = getLeftComponent();
        if (leftComponent instanceof JPanel) {
            JPanel leftPanel = (JPanel) leftComponent;
            Component[] components = leftPanel.getComponents();
            for (Component component : components) {
                if (component instanceof JPanel) {
                    JPanel panel = (JPanel) component;
                    if (panel.getLayout() instanceof BoxLayout) {
                        panel.setVisible(visible);
                        break;
                    }
                }
            }
        }
        revalidate();
        repaint();
    }
}