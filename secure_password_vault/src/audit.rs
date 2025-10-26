// ============================================================================
// Audit utilities
// ============================================================================
// This module provides utilities for displaying audit log entries in a
// formatted table view. It handles the presentation layer for audit data
// that is stored elsewhere in the application.
// ============================================================================

// Import the AuditEntry struct from the storage module, which contains
// the data structure for individual audit log entries
use crate::storage::AuditEntry;

// Import the Colorize trait from the colored crate to enable terminal
// color formatting for enhanced visual presentation
use colored::Colorize;

// AuditLogger is a zero-sized type that serves as a namespace for
// audit logging functionality. It uses a unit struct pattern since
// it doesn't need to maintain any state.
pub struct AuditLogger;

impl AuditLogger {
    /// Prints a formatted table of audit entries to the console
    ///
    /// # Arguments
    /// * `entries` - A slice of AuditEntry structs containing the audit log data
    /// * `limit` - The maximum number of entries to display (will be capped at minimum 1)
    ///
    /// # Behavior
    /// - Displays entries in reverse chronological order (most recent first)
    /// - Formats output as a bordered table with columns for timestamp, operation, service, and status
    /// - Uses color coding: blue for borders/headers, green for success, red for failures
    /// - Shows a summary count at the bottom
    pub fn print(entries: &[AuditEntry], limit: usize) {
        // Ensure limit is at least 1 to prevent displaying zero entries
        // max() returns the larger of the two values
        let limit = limit.max(1);

        // Create a vector of the most recent entries up to the specified limit
        // - iter() creates an iterator over the entries
        // - rev() reverses the order to get most recent first
        // - take(limit) limits the number of entries to display
        // - collect() gathers the references into a Vec
        let entries_to_show: Vec<_> = entries.iter().rev().take(limit).collect();

        // Print the top border of the table
        // bright_blue() applies blue color formatting to the border
        println!(
            "{}",
            "┌──────────────────────────────────────────────────────────────┐".bright_blue()
        );

        // Print the table title centered in the header
        println!(
            "{}",
            "│                       Audit Log (latest)                     │".bright_blue()
        );

        // Print the separator between header and column headers
        // Uses ┬ characters to show column divisions
        println!(
            "{}",
            "├──────────────┬────────────┬────────────────────┬─────────────┤".bright_blue()
        );

        // Print the column headers
        // Each column header is positioned to align with its data
        println!(
            "{}",
            "│   Timestamp  │ Operation  │      Service       │   Status    │".bright_blue()
        );

        // Print the separator between column headers and data rows
        // Uses ┼ characters to show column intersections
        println!(
            "{}",
            "├──────────────┼────────────┼────────────────────┼─────────────┤".bright_blue()
        );

        // Iterate through each audit entry and print its data as a table row
        for entry in &entries_to_show {
            // Format the timestamp as a human-readable date and time string
            // Format: YYYY-MM-DD HH:MM:SS (e.g., 2024-03-15 14:30:45)
            let ts = entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();

            // Get a reference to the operation string (e.g., "CREATE", "UPDATE", "DELETE")
            let op = &entry.operation;

            // Extract the service name, or use "N/A" if none is provided
            // as_deref() converts Option<String> to Option<&str>
            // unwrap_or() provides a default value if the Option is None
            let svc = entry.service.as_deref().unwrap_or("N/A");

            // Determine the status text and color based on the success flag
            // - If successful: display "SUCCESS" in bold green
            // - If failed: display "FAILED" in bold red
            let status = if entry.success {
                "SUCCESS".green().bold()
            } else {
                "FAILED".red().bold()
            };

            // Print the data row with proper column alignment
            // {:>14} - right-align timestamp in 14 characters
            // {:^10} - center-align operation in 10 characters
            // {:^20} - center-align service in 20 characters
            // {:>9} - right-align status in 9 characters (accounting for ANSI color codes)
            println!("│ {:>14} │ {:^10} │ {:^20} │ {:>9} │", ts, op, svc, status);
        }

        // Print the bottom border of the table
        // Uses └ ┴ ┘ characters to close the table
        println!(
            "{}",
            "└──────────────┴────────────┴────────────────────┴─────────────┘".bright_blue()
        );

        // Print a summary message showing how many entries are displayed
        // Uses the actual count from entries_to_show, which may be less than
        // the requested limit if there aren't enough entries available
        println!("Showing {} entrie(s).", entries_to_show.len());
    }
}
