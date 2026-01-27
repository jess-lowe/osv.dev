package models

import (
	"testing"
)

func TestAddNoteLogLevel(t *testing.T) {
	m := &ConversionMetrics{
		CVEID: "CVE-2023-1234",
		CNA:   "test-cna",
	}

	// Test default log level (Debug)
	m.AddNote("Default log level test")
	if len(m.Notes) != 1 {
		t.Errorf("Expected 1 note, got %d", len(m.Notes))
	}
	if m.Notes[0] != "Default log level test" {
		t.Errorf("Expected note 'Default log level test', got '%s'", m.Notes[0])
	}

	// Test explicit log level (Warn)
	m.AddNote("Warn log level test", Warn)
	if len(m.Notes) != 2 {
		t.Errorf("Expected 2 notes, got %d", len(m.Notes))
	}
	if m.Notes[1] != "Warn log level test" {
		t.Errorf("Expected note 'Warn log level test', got '%s'", m.Notes[1])
	}

	// Test formatting with log level
	m.AddNote("Formatted %s test", "value", Info)
	if len(m.Notes) != 3 {
		t.Errorf("Expected 3 notes, got %d", len(m.Notes))
	}
	if m.Notes[2] != "Formatted value test" {
		t.Errorf("Expected note 'Formatted value test', got '%s'", m.Notes[2])
	}
}
