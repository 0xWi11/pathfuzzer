package demo.gui;

import demo.config.ConfigChangeType;
import demo.config.ConfigManager;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.File;

public class ListPanel extends JPanel {
    private static final int BUTTON_WIDTH = 120;
    private static final int BUTTON_HEIGHT = 25;
    private static final int LIST_WIDTH = 200;
    private static final int LIST_HEIGHT = 280;
    private static final int CELL_HEIGHT = 20; // 固定单元格高度

    private final JList<String> itemList;
    private final DefaultListModel<String> listModel;
    private final ConfigManager configManager;
    private final ConfigChangeType configType;
    private final boolean editable;
    private final JTextField inputField;
    private int dragStartIndex = -1; // 用于记录拖拽开始的索引
    private JLabel itemCountLabel;  // 新增 JLabel 用于显示条目数
    private Timer timer;  // 用于定时刷新


    public ListPanel(String title, ConfigChangeType type, boolean editable) {
        this.configManager = ConfigManager.getInstance();
        this.configType = type;
        this.editable = editable;

        setBorder(BorderFactory.createTitledBorder(title));
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        // 初始化itemList - 修改为允许多选
        listModel = new DefaultListModel<>();
        itemList = new JList<>(listModel);
        itemList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        itemList.setFixedCellHeight(CELL_HEIGHT);

        itemList.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int index = itemList.locationToIndex(e.getPoint());
                if (index != -1) {
                    dragStartIndex = index;

                    // 如果没有按住Ctrl键，就清除之前的选择
                    if (!e.isControlDown()) {
                        itemList.setSelectionInterval(index, index);
                    }
                }
            }
        });

        itemList.addMouseMotionListener(new MouseAdapter() {
            @Override
            public void mouseDragged(MouseEvent e) {
                if (dragStartIndex != -1) {
                    int currentIndex = itemList.locationToIndex(e.getPoint());
                    if (currentIndex != -1) {
                        // 如果按住Ctrl键，保持原有选择
                        if (e.isControlDown()) {
                            itemList.addSelectionInterval(dragStartIndex, currentIndex);
                        } else {
                            itemList.setSelectionInterval(dragStartIndex, currentIndex);
                        }

                        // 确保当前拖拽到的项是可见的
                        itemList.ensureIndexIsVisible(currentIndex);
                    }
                }
            }
        });

        // 添加复制快捷键支持
        itemList.registerKeyboardAction(
                e -> copySelectedItems(),
                KeyStroke.getKeyStroke(KeyEvent.VK_C, Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()),
                JComponent.WHEN_FOCUSED
        );

        // 创建固定大小的面板来包含滚动面板
        JPanel scrollWrapper = new JPanel(new GridBagLayout());
        scrollWrapper.setPreferredSize(new Dimension(LIST_WIDTH, LIST_HEIGHT));

        JScrollPane scrollPane = new JScrollPane(itemList);
        GridBagConstraints scrollGbc = new GridBagConstraints();
        scrollGbc.fill = GridBagConstraints.BOTH;
        scrollGbc.weightx = 1.0;
        scrollGbc.weighty = 1.0;
        scrollWrapper.add(scrollPane, scrollGbc);

        if (editable) {
            // 创建左侧按钮面板
            JPanel buttonPanel = new JPanel();
            buttonPanel.setLayout(new GridBagLayout());
            GridBagConstraints buttonGbc = new GridBagConstraints();
            buttonGbc.gridx = 0;
            buttonGbc.fill = GridBagConstraints.HORIZONTAL;
            buttonGbc.insets = new Insets(0, 0, 5, 0);
            buttonGbc.anchor = GridBagConstraints.NORTH;

            // 创建按钮
            JButton pasteButton = createStyledButton("Paste", BUTTON_WIDTH, BUTTON_HEIGHT); // 新增粘贴按钮
            JButton loadButton = createStyledButton("Load", BUTTON_WIDTH, BUTTON_HEIGHT);
            JButton removeButton = createStyledButton("Remove", BUTTON_WIDTH, BUTTON_HEIGHT);
            JButton clearButton = createStyledButton("Clear", BUTTON_WIDTH, BUTTON_HEIGHT);
            JButton deduplicateButton = createStyledButton("Deduplicate", BUTTON_WIDTH, BUTTON_HEIGHT);
            itemCountLabel = new JLabel("Item count: 0");

            // 添加按钮行为
            pasteButton.addActionListener(e -> pasteFromClipboard()); // 新增粘贴功能
            loadButton.addActionListener(e -> loadFromFile());
            removeButton.addActionListener(e -> removeSelectedItems()); // 修改为支持删除多个选中项
            clearButton.addActionListener(e -> clearList());
            deduplicateButton.addActionListener(e -> deduplicateList());

            // 添加按钮到面板
            buttonGbc.gridy = 0;
            buttonPanel.add(pasteButton, buttonGbc);
            buttonGbc.gridy = 1;
            buttonPanel.add(loadButton, buttonGbc);
            buttonGbc.gridy = 2;
            buttonPanel.add(removeButton, buttonGbc);
            buttonGbc.gridy = 3;
            buttonPanel.add(clearButton, buttonGbc);
            buttonGbc.gridy = 4;
            buttonPanel.add(deduplicateButton, buttonGbc);
            buttonGbc.gridy = 5;
            buttonGbc.insets = new Insets(0, 15,0 , 0);
            buttonPanel.add(itemCountLabel, buttonGbc);


            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.weightx = 0.0;
            gbc.weighty = 0.0;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.insets = new Insets(5, 5, 5, 0);
            add(buttonPanel, gbc);
        }

        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        add(scrollWrapper, gbc);

        if (editable) {
            JPanel bottomPanel = new JPanel();
            bottomPanel.setLayout(new GridBagLayout());
            GridBagConstraints bottomGbc = new GridBagConstraints();

            JButton addButton = createStyledButton("Add", BUTTON_WIDTH, BUTTON_HEIGHT);
            this.inputField = new JTextField();

            // 添加回车键支持
            inputField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                        addInputText();
                    }
                }
            });

            bottomGbc.gridx = 0;
            bottomGbc.gridy = 0;
            bottomGbc.insets = new Insets(0, 0, 5, 0);
            bottomGbc.weightx = 0.0;
            bottomGbc.fill = GridBagConstraints.NONE;
            bottomPanel.add(addButton, bottomGbc);

            bottomGbc.gridx = 1;
            bottomGbc.weightx = 1.0;
            bottomGbc.fill = GridBagConstraints.HORIZONTAL;
            bottomGbc.anchor = GridBagConstraints.NORTHWEST;
            bottomGbc.insets = new Insets(0, 5, 5, 0);
            bottomPanel.add(inputField, bottomGbc);

            addButton.addActionListener(e -> addInputText());

            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.gridwidth = 2;
            gbc.weightx = 1.0;
            gbc.weighty = 1.0;
            gbc.anchor = GridBagConstraints.NORTH;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            add(bottomPanel, gbc);
        } else {
            this.inputField = null;
        }

        // 定时器，每隔1秒刷新一次条目数
        timer = new Timer(5000, e -> updateItemCount());
        timer.start();

        JPanel filler = new JPanel();
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        add(filler, gbc);

        configManager.addListener(this::refreshList);
        refreshList(configType);
    }

    // 复制选中项到剪贴板
    private void copySelectedItems() {
        ListSelectionModel selectionModel = itemList.getSelectionModel();
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < listModel.getSize(); i++) {
            if (selectionModel.isSelectedIndex(i)) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(listModel.getElementAt(i));
            }
        }

        if (sb.length() > 0) {
            StringSelection selection = new StringSelection(sb.toString());
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
        }
    }

    // 从剪贴板粘贴内容
    private void pasteFromClipboard() {
        try {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            String data = (String) clipboard.getData(DataFlavor.stringFlavor);
            if (data != null) {
                String[] lines = data.split("\n");
                for (String line : lines) {
                        addItem(line.trim());
                }
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Error pasting from clipboard: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    // 删除多个选中项
    private void removeSelectedItems() {
        int[] selectedIndices = itemList.getSelectedIndices();
        for (int i = selectedIndices.length - 1; i >= 0; i--) {
            String item = listModel.get(selectedIndices[i]);
            switch (configType) {
                case PAYLOAD:
                    configManager.removePayload(item);
                    break;
                case COLLECTED:
                    configManager.removeCollected(item);
                    break;
                case SUSPICIOUS:
                    configManager.removeSuspicious(item);
                    break;
                case BLACKLIST:
                    configManager.removeBlacklist(item);
                    break;
                case REMOVE:
                    configManager.removeRemove(item);
                    break;
            }
        }
    }

    // 添加单个项目的辅助方法
    private void addItem(String item) {
        switch (configType) {
            case PAYLOAD:
                configManager.addPayload(item);
                break;
            case COLLECTED:
                configManager.addCollected(item);
                break;
            case SUSPICIOUS:
                configManager.addSuspicious(item);
                break;
            case BLACKLIST:
                configManager.addBlacklist(item);
                break;
            case REMOVE:
                configManager.addRemove(item);
                break;
        }
    }

    private JButton createStyledButton(String text, int width, int height) {
        JButton button = new JButton(text);
        button.setPreferredSize(new Dimension(width, height));
        button.setMinimumSize(new Dimension(width, height));
        button.setMaximumSize(new Dimension(width, height));
        return button;
    }

    private void loadFromFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new FileNameExtensionFilter("Text Files", "txt"));

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                File selectedFile = fileChooser.getSelectedFile();
                configManager.loadFromFile(configType, selectedFile);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Error loading file: " + ex.getMessage(),
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void addInputText() {
        String input = inputField.getText();
        addItem(input);
        inputField.setText("");
    }

    private void clearList() {
        configManager.clearList(configType);
    }

    private void deduplicateList() {
        configManager.deduplicateList(configType);
    }
    private void updateItemCount() {
        int itemCount = listModel.getSize();  // 获取当前列表条目数
        itemCountLabel.setText("Item count: " + itemCount);  // 更新标签显示
    }

    private void refreshList(ConfigChangeType type) {
        if (type == this.configType) {
            listModel.clear();
            switch (type) {
                case PAYLOAD:
                    configManager.getPayloadList().forEach(listModel::addElement);
                    break;
                case COLLECTED:
                    configManager.getCollectedList().forEach(listModel::addElement);
                    break;
                case SUSPICIOUS:
                    configManager.getSuspiciousList().forEach(listModel::addElement);
                    break;
                case BLACKLIST:
                    configManager.getBlacklist().forEach(listModel::addElement);
                    break;
                case REMOVE:
                    configManager.getRemoveList().forEach(listModel::addElement);
                    break;
            }
        }
    }
}