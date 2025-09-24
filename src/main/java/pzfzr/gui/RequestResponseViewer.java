package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import pzfzr.model.OriginalRequestResponse;
import pzfzr.model.ModifiedRequestResponse;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.*;
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
    private ResizablePanel originalRequestPanel;
    private ResizablePanel modifiedRequestPanel;
    private ResizablePanel originalResponsePanel;
    private ResizablePanel modifiedResponsePanel;

    private CustomLayoutContainer layoutContainer;

    // 滚轮增强倍数
    private static final double SCROLL_MULTIPLIER = 1.0; // 200% 增强

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

        // 为每个编辑器添加滚轮增强
        enhanceScrolling(originalRequestViewer.uiComponent());
        enhanceScrolling(modifiedRequestViewer.uiComponent());
        enhanceScrolling(originalResponseViewer.uiComponent());
        enhanceScrolling(modifiedResponseViewer.uiComponent());

        // 创建四个可调整大小的面板
        originalRequestPanel = new ResizablePanel("Original Request", originalRequestViewer.uiComponent());
        modifiedRequestPanel = new ResizablePanel("Modified Request", modifiedRequestViewer.uiComponent());
        originalResponsePanel = new ResizablePanel("Original Response", originalResponseViewer.uiComponent());
        modifiedResponsePanel = new ResizablePanel("Modified Response", modifiedResponseViewer.uiComponent());

        // 创建自定义布局容器
        layoutContainer = new CustomLayoutContainer();
        layoutContainer.addPanel(originalRequestPanel);
        layoutContainer.addPanel(modifiedRequestPanel);
        layoutContainer.addPanel(originalResponsePanel);
        layoutContainer.addPanel(modifiedResponsePanel);

        // 将容器添加到主面板
        add(layoutContainer, BorderLayout.CENTER);
        add(navigationPanel, BorderLayout.SOUTH);

        // 设置按钮状态
        updateButtonState();
    }

    /**
     * 增强组件及其子组件的滚轮滚动功能
     */
    private void enhanceScrolling(Component component) {
        // 递归增强所有子组件的滚动
        enhanceComponentScrolling(component);
    }

    /**
     * 递归增强组件滚动
     */
    private void enhanceComponentScrolling(Component component) {
        // 为当前组件添加滚轮监听器
        component.addMouseWheelListener(new EnhancedMouseWheelListener());

        // 如果是容器，递归处理子组件
        if (component instanceof Container) {
            Container container = (Container) component;
            for (Component child : container.getComponents()) {
                enhanceComponentScrolling(child);
            }
        }
    }

    /**
     * 增强的鼠标滚轮监听器
     */
    private class EnhancedMouseWheelListener implements MouseWheelListener {
        @Override
        public void mouseWheelMoved(MouseWheelEvent e) {
            // 寻找最近的JScrollPane
            JScrollPane scrollPane = findScrollPane(e.getComponent());
            if (scrollPane != null) {
                // 消费原始事件，避免重复处理
                e.consume();

                // 获取垂直滚动条
                JScrollBar verticalScrollBar = scrollPane.getVerticalScrollBar();
                if (verticalScrollBar != null && verticalScrollBar.isVisible()) {
                    // 计算增强后的滚动量
                    int scrollAmount = e.getUnitsToScroll();
                    int enhancedScrollAmount = (int) (scrollAmount * SCROLL_MULTIPLIER);

                    // 获取当前值和单位增量
                    int currentValue = verticalScrollBar.getValue();
                    int unitIncrement = verticalScrollBar.getUnitIncrement(1);

                    // 计算新的滚动位置
                    int newValue = currentValue + (enhancedScrollAmount * unitIncrement);

                    // 确保在有效范围内
                    newValue = Math.max(verticalScrollBar.getMinimum(),
                            Math.min(verticalScrollBar.getMaximum() - verticalScrollBar.getVisibleAmount(), newValue));

                    // 设置新值
                    verticalScrollBar.setValue(newValue);
                }
            }
        }

        /**
         * 向上查找JScrollPane
         */
        private JScrollPane findScrollPane(Component component) {
            Component current = component;
            while (current != null) {
                if (current instanceof JScrollPane) {
                    return (JScrollPane) current;
                }
                current = current.getParent();
            }
            return null;
        }
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
     * 可调整大小的面板 - 完全自主控制折叠
     */
    private static class ResizablePanel extends JPanel {
        private final String title;
        private final Component content;
        private boolean isCollapsed = false;
        private boolean isDragging = false;
        private Point dragStart;
        private CustomLayoutContainer parentContainer;

        private JPanel titlePanel;
        private JButton collapseButton;
        private int preferredWidth = 300; // 默认宽度
        private int collapsedWidth = 30;  // 折叠宽度

        public ResizablePanel(String title, Component content) {
            super();
            this.title = title;
            this.content = content;

            // 不使用布局管理器，手动控制
            setLayout(null);
            setupPanel();
            setupDragListeners();
        }

        private void setupPanel() {
            // 创建标题栏
            titlePanel = new JPanel(new BorderLayout());
            titlePanel.setBackground(new Color(248, 249, 250));
            titlePanel.setBorder(BorderFactory.createEmptyBorder(1, 4, 1, 4)); // 修改：减小左右边距以适应30px宽度
            titlePanel.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));

            JLabel titleLabel = new JLabel(title);
            titleLabel.setFont(titleLabel.getFont().deriveFont(Font.PLAIN, 9f)); // 修改：减小字体大小
            titleLabel.setForeground(new Color(52, 58, 64));

            // 创建按钮面板
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 1, 0)); // 修改：进一步减小间距
            buttonPanel.setOpaque(false);

            // 折叠按钮
            collapseButton = new JButton("−");
            collapseButton.setFont(new Font(Font.MONOSPACED, Font.BOLD, 10)); // 修改：减小字体大小
            collapseButton.setPreferredSize(new Dimension(15, 15)); // 修改：减小按钮大小
            collapseButton.setFocusPainted(false);
            collapseButton.setBorderPainted(false);
            collapseButton.setContentAreaFilled(false);
            collapseButton.setForeground(new Color(108, 117, 125));
            collapseButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            collapseButton.setToolTipText("折叠面板");

            // 按钮悬停效果
            collapseButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    collapseButton.setForeground(new Color(52, 58, 64));
                    collapseButton.setContentAreaFilled(true);
                    collapseButton.setBackground(new Color(233, 236, 239));
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    collapseButton.setForeground(new Color(108, 117, 125));
                    collapseButton.setContentAreaFilled(false);
                }
            });

            collapseButton.addActionListener(e -> toggleCollapse());

            // 折叠状态下不显示拖拽图标和标题，只显示按钮
            buttonPanel.add(collapseButton);

            titlePanel.add(titleLabel, BorderLayout.CENTER);
            titlePanel.add(buttonPanel, BorderLayout.EAST);

            // 添加组件
            add(titlePanel);
            add(content);

            // 设置边框
            setBorder(new ModernBorder());
            setBackground(Color.WHITE);
        }

        private void toggleCollapse() {
            isCollapsed = !isCollapsed;

            if (isCollapsed) {
                collapseButton.setText("+");
                collapseButton.setToolTipText("展开面板");
                content.setVisible(false);
                // 折叠状态下隐藏标题文字，只保留按钮
                titlePanel.removeAll();
                JPanel buttonOnlyPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
                buttonOnlyPanel.setOpaque(false);
                buttonOnlyPanel.add(collapseButton);
                titlePanel.add(buttonOnlyPanel, BorderLayout.CENTER);
                titlePanel.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
            } else {
                collapseButton.setText("−");
                collapseButton.setToolTipText("折叠面板");
                content.setVisible(true);
                // 展开状态下恢复原有布局
                titlePanel.removeAll();

                JLabel titleLabel = new JLabel(title);
                titleLabel.setFont(titleLabel.getFont().deriveFont(Font.PLAIN, 9f));
                titleLabel.setForeground(new Color(52, 58, 64));

                JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 1, 0));
                buttonPanel.setOpaque(false);
                buttonPanel.add(collapseButton);

                titlePanel.add(titleLabel, BorderLayout.CENTER);
                titlePanel.add(buttonPanel, BorderLayout.EAST);
                titlePanel.setBorder(BorderFactory.createEmptyBorder(1, 4, 1, 4));
            }

            titlePanel.revalidate();
            titlePanel.repaint();

            // 通知父容器重新布局
            if (parentContainer != null) {
                parentContainer.layoutPanels();
            }
        }

        @Override
        public void setBounds(int x, int y, int width, int height) {
            super.setBounds(x, y, width, height);

            // 手动布局子组件
            if (titlePanel != null && content != null) {
                int titleHeight = 15; // 修改：将标题高度设置为15像素
                titlePanel.setBounds(0, 0, width, titleHeight);

                if (isCollapsed) {
                    content.setBounds(0, titleHeight, 0, 0); // 完全隐藏
                } else {
                    content.setBounds(0, titleHeight, width, height - titleHeight);
                }
            }
        }

        @Override
        public Dimension getPreferredSize() {
            if (isCollapsed) {
                return new Dimension(30, 15); // 修改：折叠时宽度为30像素
            } else {
                return new Dimension(preferredWidth, 400);
            }
        }

        @Override
        public Dimension getMinimumSize() {
            if (isCollapsed) {
                return new Dimension(30, 15); // 修改：最小宽度也设置为30像素
            } else {
                return new Dimension(200, 150);
            }
        }

        private void setupDragListeners() {
            MouseAdapter dragListener = new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (SwingUtilities.isLeftMouseButton(e) && !isOverButton(e)) {
                        isDragging = true;
                        dragStart = e.getPoint();
                        SwingUtilities.convertPointToScreen(dragStart, ResizablePanel.this);
                        setBorder(new ModernBorder(new Color(13, 110, 253), true));
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (isDragging) {
                        isDragging = false;
                        setBorder(new ModernBorder());

                        if (parentContainer != null) {
                            Point currentPoint = e.getLocationOnScreen();
                            parentContainer.handleDrop(ResizablePanel.this, currentPoint);
                        }
                    }
                }

                @Override
                public void mouseDragged(MouseEvent e) {
                    if (isDragging && parentContainer != null) {
                        Point currentPoint = e.getLocationOnScreen();
                        parentContainer.handleDragOver(ResizablePanel.this, currentPoint);
                    }
                }

                @Override
                public void mouseEntered(MouseEvent e) {
                    if (!isDragging) {
                        setBorder(new ModernBorder(new Color(206, 212, 218), false));
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
        }

        private boolean isOverButton(MouseEvent e) {
            Component deepestComponent = SwingUtilities.getDeepestComponentAt(this, e.getX(), e.getY());
            return deepestComponent instanceof JButton;
        }

        public String getTitle() {
            return title;
        }

        public boolean isCollapsed() {
            return isCollapsed;
        }

        public void setParentContainer(CustomLayoutContainer container) {
            this.parentContainer = container;
        }

        public int getPreferredWidth() {
            return preferredWidth;
        }

        public void setPreferredWidth(int width) {
            this.preferredWidth = width;
        }
    }

    /**
     * 自定义布局容器 - 手动控制所有布局
     */
    private static class CustomLayoutContainer extends JPanel {
        private final List<ResizablePanel> panels;
        private final List<ResizableHandle> handles;
        private ResizablePanel draggedPanel;

        public CustomLayoutContainer() {
            super();
            setLayout(null); // 不使用布局管理器
            this.panels = new ArrayList<>();
            this.handles = new ArrayList<>();
            setBackground(new Color(245, 245, 245));
        }

        public void addPanel(ResizablePanel panel) {
            panels.add(panel);
            panel.setParentContainer(this);
            add(panel);

            // 如果不是第一个面板，添加调整柄
            if (panels.size() > 1) {
                ResizableHandle handle = new ResizableHandle(this, panels.size() - 2);
                handles.add(handle);
                add(handle);
            }

            layoutPanels();
        }

        public void layoutPanels() {
            if (panels.isEmpty()) return;

            int totalWidth = getWidth();
            int totalHeight = getHeight();
            int handleWidth = 5;

            // 计算面板宽度
            int availableWidth = totalWidth - (handles.size() * handleWidth);
            int expandedPanelCount = 0;
            int collapsedTotalWidth = 0;

            for (ResizablePanel panel : panels) {
                if (panel.isCollapsed()) {
                    collapsedTotalWidth += panel.getPreferredSize().width;
                } else {
                    expandedPanelCount++;
                }
            }

            int expandedPanelWidth = expandedPanelCount > 0 ?
                    Math.max(200, (availableWidth - collapsedTotalWidth) / expandedPanelCount) : 0;

            // 设置面板位置
            int x = 0;
            for (int i = 0; i < panels.size(); i++) {
                ResizablePanel panel = panels.get(i);
                int panelWidth = panel.isCollapsed() ? panel.getPreferredSize().width : expandedPanelWidth;

                panel.setBounds(x, 0, panelWidth, totalHeight);
                x += panelWidth;

                // 设置调整柄位置
                if (i < handles.size()) {
                    handles.get(i).setBounds(x, 0, handleWidth, totalHeight);
                    x += handleWidth;
                }
            }

            repaint();
        }

        @Override
        public void setBounds(int x, int y, int width, int height) {
            super.setBounds(x, y, width, height);
            layoutPanels();
        }

        public void handleDragOver(ResizablePanel draggedPanel, Point screenPoint) {
            this.draggedPanel = draggedPanel;
            repaint();
        }

        public void handleDrop(ResizablePanel draggedPanel, Point screenPoint) {
            Point containerPoint = new Point(screenPoint);
            SwingUtilities.convertPointFromScreen(containerPoint, this);

            int newIndex = getDropIndex(containerPoint);
            int oldIndex = panels.indexOf(draggedPanel);

            if (oldIndex != -1 && newIndex != oldIndex && newIndex >= 0 && newIndex < panels.size()) {
                panels.remove(oldIndex);
                panels.add(newIndex, draggedPanel);
                layoutPanels();
            }
        }

        private int getDropIndex(Point point) {
            int panelCount = panels.size();
            if (panelCount == 0) return 0;

            int totalWidth = getWidth();
            int panelWidth = totalWidth / panelCount;
            int index = point.x / panelWidth;

            return Math.max(0, Math.min(index, panelCount - 1));
        }
    }

    /**
     * 调整柄组件 - 用于调整面板宽度
     */
    private static class ResizableHandle extends JComponent {
        private final CustomLayoutContainer parent;
        private final int panelIndex;
        private boolean isDragging = false;
        private int dragStartX;

        public ResizableHandle(CustomLayoutContainer parent, int panelIndex) {
            this.parent = parent;
            this.panelIndex = panelIndex;
            setCursor(Cursor.getPredefinedCursor(Cursor.E_RESIZE_CURSOR));
            setBackground(new Color(200, 200, 200));
            addMouseListener(new ResizeMouseListener());
            addMouseMotionListener(new ResizeMouseListener());
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            g.setColor(new Color(233, 236, 239));
            g.fillRect(0, 0, getWidth(), getHeight());
        }

        private class ResizeMouseListener extends MouseAdapter {
            @Override
            public void mousePressed(MouseEvent e) {
                isDragging = true;
                dragStartX = e.getXOnScreen();
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                isDragging = false;
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                if (isDragging && panelIndex < parent.panels.size()) {
                    int deltaX = e.getXOnScreen() - dragStartX;
                    ResizablePanel leftPanel = parent.panels.get(panelIndex);

                    if (!leftPanel.isCollapsed()) {
                        int newWidth = Math.max(200, leftPanel.getPreferredWidth() + deltaX);
                        leftPanel.setPreferredWidth(newWidth);
                        parent.layoutPanels();
                    }

                    dragStartX = e.getXOnScreen();
                }
            }
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
            this(new Color(222, 226, 230), false);
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
}