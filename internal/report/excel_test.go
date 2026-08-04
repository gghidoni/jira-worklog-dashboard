package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"
)

func TestBuildExcelAppliesWorklogGroupingRules(t *testing.T) {
	t.Parallel()

	location := time.FixedZone("Europe/Rome", 2*60*60)
	worklogs := []Worklog{
		worklog("TL-1", "Task misto", "Andrea Faraone", "andrea", "2026-07-01T09:00:00.000+0200", "Analisi", 3600),
		worklog("TL-1", "Task misto", "Andrea Faraone", "andrea", "2026-07-02T09:00:00.000+0200", "", 1800),
		worklog("TL-1", "Task misto", "Andrea Faraone", "andrea", "2026-07-03T09:00:00.000+0200", "   ", 900),
		worklog("TL-2", "Task senza descrizioni", "Andrea Faraone", "andrea", "2026-07-04T09:00:00.000+0200", "", 7200),
		worklog("TL-3", "Task giugno", "Mario Rossi", "mario", "2026-06-15T09:00:00.000+0200", "Sviluppo", 5400),
	}

	contents, err := BuildExcel(Options{
		From:     time.Date(2026, time.June, 1, 0, 0, 0, 0, location),
		To:       time.Date(2026, time.July, 31, 0, 0, 0, 0, location),
		Location: location,
	}, worklogs)
	if err != nil {
		t.Fatalf("BuildExcel() error = %v", err)
	}

	book, err := excelize.OpenReader(bytes.NewReader(contents))
	if err != nil {
		t.Fatalf("open generated workbook: %v", err)
	}
	t.Cleanup(func() { _ = book.Close() })

	wantSheets := []string{"Riepilogo", "Andrea Faraone", "Mario Rossi"}
	if got := book.GetSheetList(); !equalStrings(got, wantSheets) {
		t.Fatalf("sheet list = %v, want %v", got, wantSheets)
	}
	for _, sheet := range wantSheets {
		view, err := book.GetSheetView(sheet, 0)
		if err != nil {
			t.Fatalf("read %s sheet view: %v", sheet, err)
		}
		if view.ShowGridLines == nil || *view.ShowGridLines {
			t.Errorf("gridlines are visible on %s", sheet)
		}
	}

	rows, err := book.GetRows("Andrea Faraone")
	if err != nil {
		t.Fatalf("read user rows: %v", err)
	}
	allCells := strings.Join(flattenRows(rows), "\n")
	for _, expected := range []string{"TL-1", "TL-2", "Task misto", "Task senza descrizioni", "Analisi", "Worklog senza descrizione (2)"} {
		if !strings.Contains(allCells, expected) {
			t.Errorf("generated sheet does not contain %q", expected)
		}
	}
	if count := strings.Count(allCells, "Worklog senza descrizione"); count != 1 {
		t.Errorf("undescribed worklog aggregate count = %d, want 1", count)
	}
	if strings.Contains(allCells, "(nessuna descrizione)") {
		t.Error("all-undescribed task generated an unwanted detail row")
	}

	issueCell := findCell(rows, "TL-1")
	if issueCell == "" {
		t.Fatal("could not find TL-1 cell")
	}
	hasLink, target, err := book.GetCellHyperLink("Andrea Faraone", issueCell)
	if err != nil {
		t.Fatalf("read task hyperlink: %v", err)
	}
	if !hasLink || target != "https://jira.example.test/browse/TL-1" {
		t.Errorf("task hyperlink = (%v, %q), want Jira issue URL", hasLink, target)
	}

	summaryRows, err := book.GetRows(summarySheet)
	if err != nil {
		t.Fatalf("read summary rows: %v", err)
	}
	summary := strings.Join(flattenRows(summaryRows), "\n")
	for _, expected := range []string{"Giugno 2026", "Luglio 2026", "Andrea Faraone", "Mario Rossi"} {
		if !strings.Contains(summary, expected) {
			t.Errorf("summary does not contain %q", expected)
		}
	}

	drawing := workbookFile(t, contents, "xl/drawings/drawing1.xml")
	if !strings.Contains(drawing, "<xdr:from><xdr:col>0</xdr:col>") || !strings.Contains(drawing, "<xdr:row>13</xdr:row>") {
		t.Errorf("summary chart is not anchored below the summary table: %s", drawing)
	}
}

func TestBuildExcelUsesSafeUniqueUserSheetNames(t *testing.T) {
	t.Parallel()

	contents, err := BuildExcel(Options{
		From: time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, time.July, 31, 0, 0, 0, 0, time.UTC),
	}, []Worklog{
		worklog("TL-1", "One", "Utente/Team", "one", "2026-07-01T09:00:00Z", "", 3600),
		worklog("TL-2", "Two", "Utente:Team", "two", "2026-07-01T09:00:00Z", "", 3600),
	})
	if err != nil {
		t.Fatalf("BuildExcel() error = %v", err)
	}

	book, err := excelize.OpenReader(bytes.NewReader(contents))
	if err != nil {
		t.Fatalf("open generated workbook: %v", err)
	}
	t.Cleanup(func() { _ = book.Close() })
	if got, want := book.GetSheetList(), []string{"Riepilogo", "Utente-Team", "Utente-Team (2)"}; !equalStrings(got, want) {
		t.Fatalf("sheet list = %v, want %v", got, want)
	}
}

func worklog(key, summary, user, accountID, started, comment string, seconds int) Worklog {
	return Worklog{
		IssueKey:          key,
		IssueSummary:      summary,
		IssueURL:          "https://jira.example.test/browse/" + key,
		EstimateSeconds:   8 * 3600,
		Started:           started,
		Comment:           comment,
		AuthorAccountID:   accountID,
		AuthorDisplayName: user,
		TimeSpentSeconds:  seconds,
	}
}

func flattenRows(rows [][]string) []string {
	var cells []string
	for _, row := range rows {
		cells = append(cells, row...)
	}
	return cells
}

func findCell(rows [][]string, value string) string {
	for rowIndex, row := range rows {
		for columnIndex, cellValue := range row {
			if cellValue == value {
				return cell(columnIndex+1, rowIndex+1)
			}
		}
	}
	return ""
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func workbookFile(t *testing.T, workbook []byte, name string) string {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(workbook), int64(len(workbook)))
	if err != nil {
		t.Fatalf("open workbook archive: %v", err)
	}
	for _, file := range archive.File {
		if file.Name != name {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		contents, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close %s: %v", name, closeErr)
		}
		return string(contents)
	}
	t.Fatalf("workbook does not contain %s", name)
	return ""
}
