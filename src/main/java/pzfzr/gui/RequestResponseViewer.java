package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import pzfzr.model.OriginalRequestResponse;
import pzfzr.model.ModifiedRequestResponse;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.KeyEvent;
import java.awt.geom.RoundRectangle2D;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class RequestResponseViewer extends JPanel {
    private final HttpRequestEditor originalRequestViewer;
    private final HttpRequestEditor modifiedRequestViewer;
    private final HttpResponseEditor originalResponseViewer;
    private final HttpResponseEditor modifiedResponseViewer;

    private final JButton previousButton;
    private final JButton nextButton;
    private HistoryPanel historyPanel;

    // 添加对当前数据的弱引用
    private WeakReference<OriginalRequestResponse> currentOriginal;
    private WeakReference<ModifiedRequestResponse> currentModified;

    // 四个可拖拽的面板
    private DraggablePanel originalRequestPanel;
    private DraggablePanel modifiedRequestPanel;
    private DraggablePanel originalResponsePanel;
    private DraggablePanel modifiedResponsePanel;

    private ResizablePanelContainer panelContainer;

    public RequestResponseViewer(MontoyaApi api) {
        super(new BorderLayout());

        // 创建导航按钮（保持功能，但暂时隐藏）
        previousButton = new JButton("▲ Previous");
        nextButton = new JButton("▼ Next");

        JPanel navigationPanel = createNavigationPanel();

        // 创建四个编辑器
        originalRequestViewer = api.userInterface().createHttpRequestEditor(READ_ONLY);
        modifiedRequestViewer = api.userInterface().createHttpRequestEditor(READ_ONLY);
        originalResponseViewer = api.userInterface().createHttpResponseEditor(READ_ONLY);
        modifiedResponseViewer = api.userInterface().createHttpResponseEditor(READ_ONLY);

        // 创建四个可拖拽面板
        originalRequestPanel = new DraggablePanel("Original Request", originalRequestViewer.uiComponent());
        modifiedRequestPanel = new DraggablePanel("Modified Request", modifiedRequestViewer.uiComponent());
        originalResponsePanel = new DraggablePanel("Original Response", originalResponseViewer.uiComponent());
        modifiedResponsePanel = new DraggablePanel("Modified Response", modifiedResponseViewer.uiComponent());

        // 创建可调整大小的面板容器
        panelContainer = new ResizablePanelContainer();
        panelContainer.addPanel(originalRequestPanel);
        panelContainer.addPanel(modifiedRequestPanel);
        panelContainer.addPanel(originalResponsePanel);
        panelContainer.addPanel(modifiedResponsePanel);

        // 将容器添加到主面板
        add(panelContainer, BorderLayout.CENTER);
        add(navigationPanel, BorderLayout.SOUTH);

        // 设置按钮状态
        updateButtonState();
    }

    private JPanel createNavigationPanel() {
        JPanel navigationPanel = new JPanel();
        navigationPanel.setLayout(new BoxLayout(navigationPanel, BoxLayout.X_AXIS));

        // 设置按钮样式
        Dimension buttonSize = new Dimension(120, 25);
        Color defaultColor = new Color(238, 238, 238);
        Color hoverColor = new Color(200, 200, 200);

        setupButton(previousButton, buttonSize, defaultColor, hoverColor, "Previous (Ctrl+Shift+Z)");
        setupButton(nextButton, buttonSize, defaultColor, hoverColor, "Next (Ctrl+Shift+X)");

        // 添加快捷键支持
        setupKeyboardShortcuts(navigationPanel);

        navigationPanel.add(Box.createHorizontalGlue());
        navigationPanel.add(previousButton);
        navigationPanel.add(Box.createHorizontalStrut(10));
        navigationPanel.add(nextButton);
        navigationPanel.add(Box.createHorizontalGlue());

        navigationPanel.setVisible(false); // 暂时隐藏
        return navigationPanel;
    }

    private void setupButton(JButton button, Dimension size, Color defaultColor, Color hoverColor, String tooltip) {
        button.setPreferredSize(size);
        button.setMaximumSize(size);
        button.setBackground(defaultColor);
        button.setContentAreaFilled(true);
        button.setToolTipText(tooltip);

        button.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                button.setBackground(hoverColor);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                button.setBackground(defaultColor);
            }
        });
    }

    private void setupKeyboardShortcuts(JPanel navigationPanel) {
        String previousActionKey = "previousAction";
        String nextActionKey = "nextAction";

        Action previousAction = new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                if (historyPanel != null && historyPanel.hasPrevious()) {
                    historyPanel.selectPrevious();
                }
            }
        };

        Action nextAction = new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                if (historyPanel != null && historyPanel.hasNext()) {
                    historyPanel.selectNext();
                }
            }
        };

        KeyStroke previousKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_Z, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK);
        KeyStroke nextKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_X, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK);

        navigationPanel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(previousKeyStroke, previousActionKey);
        navigationPanel.getActionMap().put(previousActionKey, previousAction);
        navigationPanel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(nextKeyStroke, nextActionKey);
        navigationPanel.getActionMap().put(nextActionKey, nextAction);
    }

    public void setHistoryPanel(HistoryPanel historyPanel) {
        this.historyPanel = historyPanel;
        previousButton.addActionListener(e -> historyPanel.selectPrevious());
        nextButton.addActionListener(e -> historyPanel.selectNext());
    }

    public void updateViewers(OriginalRequestResponse original, ModifiedRequestResponse modified) {
        clearViewers();

        if (original != null && modified != null) {
            currentOriginal = new WeakReference<>(original);
            currentModified = new WeakReference<>(modified);

            SwingUtilities.invokeLater(() -> {
                try {
                    originalRequestViewer.setRequest(original.getOriginalRequest());
                    originalResponseViewer.setResponse(original.getOriginalResponse());
                    modifiedRequestViewer.setRequest(modified.getModifiedRequest());
                    modifiedRequestViewer.setSearchExpression(modified.getExpression());
                    modifiedResponseViewer.setResponse(modified.getModifiedResponse());
                } catch (Exception e) {
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
                originalRequestViewer.setRequest(null);
                originalResponseViewer.setResponse(null);
                modifiedRequestViewer.setRequest(null);
                modifiedResponseViewer.setResponse(null);

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

    public void cleanup() {
        clearViewers();
        previousButton.removeActionListener(l -> {});
        nextButton.removeActionListener(l -> {});
        historyPanel = null;
    }

    public void setNavigationVisible(boolean visible) {
        Component[] components = getComponents();
        for (Component component : components) {
            if (component instanceof JPanel) {
                JPanel panel = (JPanel) component;
                if (panel.getLayout() instanceof BoxLayout) {
                    panel.setVisible(visible);
                    break;
                }
            }
        }
        revalidate();
        repaint();
    }

    /**
     * 现代化可拖拽面板类
     */
    private static class DraggablePanel extends JPanel {
        private final String title;
        private final Component content;
        private boolean isDragging = false;
        private Point dragStart;
        private ResizablePanelContainer parentContainer;

        public DraggablePanel(String title, Component content) {
            super(new BorderLayout());
            this.title = title;
            this.content = content;

            setupPanel();
            setupDragListeners();
        }

        private void setupPanel() {
            // 创建现代化标题栏
            JPanel titlePanel = new JPanel(new BorderLayout());
            titlePanel.setBackground(new Color(248, 249, 250)); // 浅灰色背景
            titlePanel.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
            titlePanel.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));

            JLabel titleLabel = new JLabel(title);
            titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 11f));
            titleLabel.setForeground(new Color(52, 58, 64)); // 深灰色文字

            // 添加拖拽图标
            JLabel dragIcon = new JLabel("⋮⋮");
            dragIcon.setForeground(new Color(134, 142, 150));
            dragIcon.setFont(dragIcon.getFont().deriveFont(Font.BOLD, 10f));

            titlePanel.add(titleLabel, BorderLayout.CENTER);
            titlePanel.add(dragIcon, BorderLayout.EAST);

            // 设置现代化的细边框
            setBorder(new ModernBorder());
            setBackground(Color.WHITE);

            // 添加组件
            add(titlePanel, BorderLayout.NORTH);
            add(content, BorderLayout.CENTER);
        }

        private void setupDragListeners() {
            MouseAdapter dragListener = new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (SwingUtilities.isLeftMouseButton(e) && isInTitleArea(e)) {
                        isDragging = true;
                        dragStart = e.getPoint();
                        SwingUtilities.convertPointToScreen(dragStart, DraggablePanel.this);

                        // 高亮面板表示正在拖拽 - 使用现代化的蓝色边框
                        setBorder(new ModernBorder(new Color(13, 110, 253), true)); // Bootstrap蓝色
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (isDragging) {
                        isDragging = false;

                        // 恢复原始边框
                        setBorder(new ModernBorder());

                        // 处理拖放
                        if (parentContainer != null) {
                            Point currentPoint = e.getLocationOnScreen();
                            parentContainer.handleDrop(DraggablePanel.this, currentPoint);
                        }
                    }
                }

                @Override
                public void mouseDragged(MouseEvent e) {
                    if (isDragging && parentContainer != null) {
                        Point currentPoint = e.getLocationOnScreen();
                        parentContainer.handleDragOver(DraggablePanel.this, currentPoint);
                    }
                }

                @Override
                public void mouseEntered(MouseEvent e) {
                    if (!isDragging) {
                        setBorder(new ModernBorder(new Color(206, 212, 218), false)); // 悬停效果
                    }
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    if (!isDragging) {
                        setBorder(new ModernBorder());
                    }
                }
            };

            addMouseListener(dragListener);
            addMouseMotionListener(dragListener);

            // 也为标题面板添加监听器
            Component titleComponent = ((BorderLayout) getLayout()).getLayoutComponent(BorderLayout.NORTH);
            if (titleComponent != null) {
                titleComponent.addMouseListener(dragListener);
                titleComponent.addMouseMotionListener(dragListener);
            }
        }

        private boolean isInTitleArea(MouseEvent e) {
            Component titleComponent = ((BorderLayout) getLayout()).getLayoutComponent(BorderLayout.NORTH);
            if (titleComponent != null) {
                Rectangle titleBounds = titleComponent.getBounds();
                return titleBounds.contains(e.getPoint());
            }
            return false;
        }

        public String getTitle() {
            return title;
        }

        public void setParentContainer(ResizablePanelContainer container) {
            this.parentContainer = container;
        }
    }

    /**
     * 现代化边框类
     */
    private static class ModernBorder implements Border {
        private final Color borderColor;
        private final boolean isSelected;
        private static final int BORDER_WIDTH = 1;
        private static final int BORDER_RADIUS = 6;

        public ModernBorder() {
            this(new Color(222, 226, 230), false); // 默认边框颜色
        }

        public ModernBorder(Color borderColor, boolean isSelected) {
            this.borderColor = borderColor;
            this.isSelected = isSelected;
        }

        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Graphics2D g2d = (Graphics2D) g.create();
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            if (isSelected) {
                g2d.setStroke(new BasicStroke(2.0f));
            } else {
                g2d.setStroke(new BasicStroke(BORDER_WIDTH));
            }

            g2d.setColor(borderColor);

            // 绘制圆角矩形边框
            g2d.drawRoundRect(x, y, width - 1, height - 1, BORDER_RADIUS, BORDER_RADIUS);
            g2d.dispose();
        }

        @Override
        public Insets getBorderInsets(Component c) {
            return new Insets(BORDER_WIDTH + 1, BORDER_WIDTH + 1, BORDER_WIDTH + 1, BORDER_WIDTH + 1);
        }

        @Override
        public boolean isBorderOpaque() {
            return false;
        }
    }

    /**
     * 可调整大小的面板容器类（使用嵌套的JSplitPane）
     */
    private static class ResizablePanelContainer extends JPanel {
        private final List<DraggablePanel> panels;
        private DraggablePanel draggedPanel;
        private JSplitPane mainSplit;
        private JSplitPane leftSplit;
        private JSplitPane rightSplit;

        public ResizablePanelContainer() {
            super(new BorderLayout());
            this.panels = new ArrayList<>();
            setupSplitPanes();
        }

        private void setupSplitPanes() {
            // 创建三个嵌套的JSplitPane来支持四个面板的宽度调节
            leftSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            rightSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplit, rightSplit);

            // 设置分割条样式
            customizeSplitPane(mainSplit);
            customizeSplitPane(leftSplit);
            customizeSplitPane(rightSplit);

            // 设置初始比例
            mainSplit.setResizeWeight(0.5); // 左右各占一半
            leftSplit.setResizeWeight(0.5); // 左边两个面板各占一半
            rightSplit.setResizeWeight(0.5); // 右边两个面板各占一半

            add(mainSplit, BorderLayout.CENTER);
        }

        private void customizeSplitPane(JSplitPane splitPane) {
            splitPane.setDividerSize(5); // 细分割条
            splitPane.setBorder(null);
            splitPane.setOpaque(false);

            // 自定义分割条颜色
            splitPane.setUI(new javax.swing.plaf.basic.BasicSplitPaneUI() {
                @Override
                public javax.swing.plaf.basic.BasicSplitPaneDivider createDefaultDivider() {
                    return new javax.swing.plaf.basic.BasicSplitPaneDivider(this) {
                        @Override
                        public void paint(Graphics g) {
                            g.setColor(new Color(233, 236, 239)); // 浅灰色分割条
                            g.fillRect(0, 0, getSize().width, getSize().height);
                        }
                    };
                }
            });
        }

        public void addPanel(DraggablePanel panel) {
            panels.add(panel);
            panel.setParentContainer(this);
            refreshLayout();
        }

        public void handleDragOver(DraggablePanel draggedPanel, Point screenPoint) {
            this.draggedPanel = draggedPanel;
            // 在拖拽过程中可以添加视觉指示器
            repaint();
        }

        public void handleDrop(DraggablePanel draggedPanel, Point screenPoint) {
            // 将屏幕坐标转换为容器坐标
            Point containerPoint = new Point(screenPoint);
            SwingUtilities.convertPointFromScreen(containerPoint, this);

            // 确定拖拽位置应该插入的索引
            int newIndex = getDropIndex(containerPoint);

            if (newIndex >= 0 && newIndex < panels.size()) {
                // 移动面板到新位置
                int oldIndex = panels.indexOf(draggedPanel);
                if (oldIndex != -1 && oldIndex != newIndex) {
                    panels.remove(oldIndex);

                    // 调整索引（如果从前面移到后面）
                    int adjustedIndex = newIndex;
                    if (oldIndex < newIndex) {
                        adjustedIndex--;
                    }

                    panels.add(adjustedIndex, draggedPanel);
                    refreshLayout();
                }
            }
        }

        private int getDropIndex(Point point) {
            int panelCount = panels.size();
            if (panelCount == 0) return 0;

            int panelWidth = getWidth() / panelCount;
            int index = point.x / panelWidth;

            // 如果点击位置超过中点，插入到下一个位置
            int remainder = point.x % panelWidth;
            if (remainder > panelWidth / 2) {
                index++;
            }

            return Math.max(0, Math.min(index, panelCount));
        }

        private void refreshLayout() {
            if (panels.size() >= 4) {
                leftSplit.setLeftComponent(panels.get(0));
                leftSplit.setRightComponent(panels.get(1));
                rightSplit.setLeftComponent(panels.get(2));
                rightSplit.setRightComponent(panels.get(3));
            }
            revalidate();
            repaint();
        }
    }
}