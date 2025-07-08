package demo.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import demo.core.CookieChanger;
import demo.core.CookieChanger.HeaderEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel for managing header entries in the CookieChanger
 */
public class CookieChangerPanel extends JPanel {

    private final MontoyaApi api;
    private final Logging logging;
    private final CookieChanger cookieChanger;
    private final JTable headerTable;
    private final HeaderTableModel tableModel;

    public CookieChangerPanel(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.cookieChanger = CookieChanger.getInstance();

        // Use BorderLayout for the main panel
        setLayout(new BorderLayout());

        // Create a panel to hold the existing table and buttons
        JPanel topPanel = new JPanel(new BorderLayout());

        // Create the table model and table
        tableModel = new HeaderTableModel();
        headerTable = new JTable(tableModel);

        // Set up table appearance
        headerTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        headerTable.setAutoCreateRowSorter(true);

        // Center align text in cells
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        for (int i = 0; i < headerTable.getColumnCount(); i++) {
            headerTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }

        // Set column widths
        headerTable.getColumnModel().getColumn(0).setPreferredWidth(200); // Host
        headerTable.getColumnModel().getColumn(1).setPreferredWidth(150); // Header Name
        headerTable.getColumnModel().getColumn(2).setPreferredWidth(250); // Header Value

        // Create scroll pane for the table
        JScrollPane scrollPane = new JScrollPane(headerTable);

        // Create button panel
        JPanel buttonPanel = new JPanel();

        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton deleteButton = new JButton("Delete");
        JButton clearAllButton = new JButton("Clear All");
        JButton refreshButton = new JButton("Refresh");

        // Add action listeners to buttons
        addButton.addActionListener(this::addHeaderEntry);
        editButton.addActionListener(this::editHeaderEntry);
        deleteButton.addActionListener(this::deleteHeaderEntry);
        clearAllButton.addActionListener(this::clearAllEntries);
        refreshButton.addActionListener(e -> refreshTable());

        // Add buttons to panel
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(clearAllButton);
        buttonPanel.add(refreshButton);

        // Add the scroll pane (table) and button panel to the top panel
        topPanel.add(scrollPane, BorderLayout.CENTER);
        topPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add the top panel to the NORTH of the main panel
        add(topPanel, BorderLayout.NORTH);

        // The rest of the panel (BorderLayout.CENTER) will be empty space
        // Add future components here using BorderLayout.CENTER or another panel in BorderLayout.CENTER

        // Initial table refresh
        refreshTable();
    }

    /**
     * Refresh the table with the latest data from CookieChanger
     */
    public void refreshTable() {
        tableModel.refreshData();
    }

    /**
     * Add a new header entry
     */
    private void addHeaderEntry(ActionEvent e) {
        HeaderEntryDialog dialog = new HeaderEntryDialog(SwingUtilities.getWindowAncestor(this), "Add Header Entry");
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            HeaderEntry entry = dialog.getHeaderEntry();
            cookieChanger.storeHeaderEntry(entry);
            refreshTable();
            logging.logToOutput("[CookieChanger] Added new header entry: " + entry.getHost() + " - " + entry.getHeaderName());
        }
    }

    /**
     * Edit an existing header entry
     */
    private void editHeaderEntry(ActionEvent e) {
        int selectedRow = headerTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a header entry to edit.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Convert view index to model index in case the table is sorted
        int modelRow = headerTable.convertRowIndexToModel(selectedRow);
        HeaderEntry oldEntry = tableModel.getEntryAt(modelRow);

        HeaderEntryDialog dialog = new HeaderEntryDialog(SwingUtilities.getWindowAncestor(this), "Edit Header Entry", oldEntry);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            HeaderEntry newEntry = dialog.getHeaderEntry();
            cookieChanger.updateHeaderEntry(oldEntry, newEntry);
            refreshTable();
            logging.logToOutput("[CookieChanger] Updated header entry: " + newEntry.getHost() + " - " + newEntry.getHeaderName());
        }
    }

    /**
     * Delete a header entry
     */
    private void deleteHeaderEntry(ActionEvent e) {
        int selectedRow = headerTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a header entry to delete.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Convert view index to model index in case the table is sorted
        int modelRow = headerTable.convertRowIndexToModel(selectedRow);
        HeaderEntry entry = tableModel.getEntryAt(modelRow);

        int result = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to delete this header entry?\nHost: " + entry.getHost() + "\nHeader: " + entry.getHeaderName(),
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (result == JOptionPane.YES_OPTION) {
            cookieChanger.deleteHeaderEntry(entry);
            refreshTable();
            logging.logToOutput("[CookieChanger] Deleted header entry: " + entry.getHost() + " - " + entry.getHeaderName());
        }
    }

    /**
     * Clear all header entries
     */
    private void clearAllEntries(ActionEvent e) {
        int result = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to clear all header entries?",
                "Confirm Clear All",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (result == JOptionPane.YES_OPTION) {
            cookieChanger.clearAll();
            refreshTable();
            logging.logToOutput("[CookieChanger] Cleared all header entries");
        }
    }

    /**
     * Table model for the header entries
     */
    private class HeaderTableModel extends AbstractTableModel {
        private final String[] COLUMN_NAMES = {"Host", "Header Name", "Header Value"};
        private List<HeaderEntry> entries = new ArrayList<>();

        public void refreshData() {
            entries = cookieChanger.getAllHeaderEntries();
            fireTableDataChanged();
        }

        public HeaderEntry getEntryAt(int rowIndex) {
            return entries.get(rowIndex);
        }

        @Override
        public int getRowCount() {
            return entries.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            HeaderEntry entry = entries.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    return entry.getHost();
                case 1:
                    return entry.getHeaderName();
                case 2:
                    return entry.getHeaderValue();
                default:
                    return null;
            }
        }
    }

    /**
     * Dialog for adding or editing header entries
     */
    private static class HeaderEntryDialog extends JDialog {
        private final JTextField hostField;
        private final JTextField headerNameField;
        private final JTextField headerValueField;
        private boolean confirmed = false;

        public HeaderEntryDialog(Window owner, String title) {
            super(owner, title, ModalityType.APPLICATION_MODAL);

            hostField = new JTextField(30);
            headerNameField = new JTextField(30);
            headerValueField = new JTextField(30);

            initializeDialog();
        }

        public HeaderEntryDialog(Window owner, String title, HeaderEntry entry) {
            super(owner, title, ModalityType.APPLICATION_MODAL);

            hostField = new JTextField(entry.getHost(), 30);
            headerNameField = new JTextField(entry.getHeaderName(), 30);
            headerValueField = new JTextField(entry.getHeaderValue(), 30);

            initializeDialog();
        }

        private void initializeDialog() {
            JPanel panel = new JPanel(new GridBagLayout());
            GridBagConstraints constraints = new GridBagConstraints();
            constraints.fill = GridBagConstraints.HORIZONTAL;
            constraints.insets = new Insets(5, 5, 5, 5);

            // Host field
            constraints.gridx = 0;
            constraints.gridy = 0;
            panel.add(new JLabel("Host:"), constraints);

            constraints.gridx = 1;
            constraints.weightx = 1.0;
            panel.add(hostField, constraints);

            // Header name field
            constraints.gridx = 0;
            constraints.gridy = 1;
            constraints.weightx = 0.0;
            panel.add(new JLabel("Header Name:"), constraints);

            constraints.gridx = 1;
            constraints.weightx = 1.0;
            panel.add(headerNameField, constraints);

            // Header value field
            constraints.gridx = 0;
            constraints.gridy = 2;
            constraints.weightx = 0.0;
            panel.add(new JLabel("Header Value:"), constraints);

            constraints.gridx = 1;
            constraints.weightx = 1.0;
            panel.add(headerValueField, constraints);

            // Buttons
            JButton okButton = new JButton("OK");
            JButton cancelButton = new JButton("Cancel");

            okButton.addActionListener(e -> {
                if (validateFields()) {
                    confirmed = true;
                    dispose();
                }
            });

            cancelButton.addActionListener(e -> dispose());

            JPanel buttonPanel = new JPanel();
            buttonPanel.add(okButton);
            buttonPanel.add(cancelButton);

            constraints.gridx = 0;
            constraints.gridy = 3;
            constraints.gridwidth = 2;
            constraints.weightx = 1.0;
            panel.add(buttonPanel, constraints);

            getContentPane().add(panel);
            pack();
            setLocationRelativeTo(getOwner());
        }

        private boolean validateFields() {
            if (hostField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "Host field cannot be empty.", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            if (headerNameField.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "Header Name field cannot be empty.", "Validation Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            return true;
        }

        public boolean isConfirmed() {
            return confirmed;
        }

        public HeaderEntry getHeaderEntry() {
            return new HeaderEntry(
                    hostField.getText().trim(),
                    headerNameField.getText().trim(),
                    headerValueField.getText().trim()
            );
        }
    }
}