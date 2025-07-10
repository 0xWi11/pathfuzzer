package pzfzr.model;

import burp.api.montoya.logging.Logging;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CSVExporter {
    private final Logging logging;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    public CSVExporter(Logging logging, TableModel tableModel, RequestResponseSaver requestResponseSaver) {
        this.logging = logging;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
    }

    public void exportToCSV() {
        // Run the export operation in a background thread to avoid UI freezing
        executorService.submit(() -> {
            try {
                // Get the daily storage directory from RequestResponseSaver
                Path dailyStorageDir = requestResponseSaver.getDailyStorageDir();
                if (dailyStorageDir == null) {
                    logging.logToError("[CSVExporter] Failed to get daily storage directory");
                    return;
                }

                // Generate CSV filename with same format as RequestResponseSaver uses
                String csvFilename = requestResponseSaver.generateFilename("csv");
                File csvFile = new File(dailyStorageDir.toFile(), csvFilename);

                // Write data to CSV
                writeDataToCSV(csvFile);

                logging.logToOutput("[CSVExporter] Data exported to " + csvFile.getAbsolutePath());
            } catch (Exception e) {
                logging.logToError("[CSVExporter] Error exporting data to CSV: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }

    private void writeDataToCSV(File csvFile) {
        List<ModifiedRequestResponse> entries = tableModel.getAllModifiedEntries();
        if (entries.isEmpty()) {
            logging.logToOutput("[CSVExporter] No data to export");
            return;
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(csvFile))) {
            // Write header
            writer.write("\"ID\",\"Method\",\"URL\",\"Test Type\",\"Orig. Len\",\"Modif. Len\",\"Modif. Status\",\"Len Diff\",\"Modif. Time\",\"Reflect\"\n");

            // Write data rows
            for (ModifiedRequestResponse modifiedEntry : entries) {
                OriginalRequestResponse originalEntry = tableModel.findByMessageId(modifiedEntry.getOriginalMessageId());
                if (originalEntry == null) {
                    continue;
                }

                StringBuilder row = new StringBuilder();
                // ID
                row.append("\"").append(modifiedEntry.getId()).append("\",");
                // Method
                row.append("\"").append(originalEntry.getOriginalMethod()).append("\",");
                // URL - remove commas to prevent CSV structure issues
                String sanitizedUrl = originalEntry.getOriginalUrl().replace(",", "");
                row.append("\"").append(sanitizedUrl).append("\",");
                // Test Type
                row.append("\"").append(modifiedEntry.getTestType()).append("\",");
                // Original Length
                row.append("\"").append(originalEntry.getOriginalResponseLen()).append("\",");
                // Modified Length
                row.append("\"").append(modifiedEntry.getModifiedBodyLength()).append("\",");
                // Modified Status
                row.append("\"").append(modifiedEntry.getStatusCode()).append("\",");
                // Length Difference
                int origLen = originalEntry.getOriginalResponseLen();
                int modifyLen = modifiedEntry.getModifiedBodyLength();
                row.append("\"").append(Math.abs(modifyLen - origLen)).append("\",");
                // Modified Time
                row.append("\"").append(modifiedEntry.getResponseTime()).append("\",");
                // Reflect
                row.append("\"").append(modifiedEntry.getReflectType() != null ? modifiedEntry.getReflectType() : "").append("\"");

                writer.write(row.toString());
                writer.newLine();
            }
        } catch (IOException e) {
            logging.logToError("[CSVExporter] Error writing to CSV file: " + e.getMessage());
        }
    }

    public void shutdown() {
        executorService.shutdown();
    }
}