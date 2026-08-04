package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gghidoni/jira-worklog-dashboard/internal/jira"
	"github.com/xuri/excelize/v2"
)

func TestHandleExportExcelDownloadsWorkbookFromDashboardFilters(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var responseBody string
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql":
			responseBody = `{
				"isLast": true,
				"issues": [{
					"id": "1",
					"key": "TL-1",
					"fields": {
						"summary": "Task esportato",
						"project": {"id": "10", "key": "TL", "name": "Team Leader"},
						"issuetype": {"id": "100", "name": "Task"},
						"timeoriginalestimate": 28800
					}
				}]
			}`
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/TL-1/worklog":
			responseBody = `{
				"startAt": 0,
				"maxResults": 100,
				"total": 2,
				"worklogs": [{
					"id": "w1",
					"timeSpentSeconds": 5400,
					"started": "2026-07-20T09:00:00.000+0200",
					"author": {"accountId": "andrea", "displayName": "Andrea Faraone"},
					"comment": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Analisi export"}]}]}
				}, {
					"id": "w2",
					"timeSpentSeconds": 3600,
					"started": "2026-07-21T09:00:00.000+0200",
					"author": {"accountId": "mario", "displayName": "Mario Rossi"}
				}]
			}`
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("unexpected Jira request")),
				Request:    r,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(responseBody)),
			Request:    r,
		}, nil
	})}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := &App{
		cfg: Config{
			JiraBaseURL:        "https://jira.example.test",
			JiraEmail:          "test@example.test",
			JiraAPIToken:       "test-token",
			MaxRangeDays:       90,
			WorklogConcurrency: 1,
		},
		jira: jira.NewClient(jira.Config{
			BaseURL:    "https://jira.example.test",
			Timeout:    5 * time.Second,
			Logger:     logger,
			HTTPClient: httpClient,
		}),
		tz:     time.FixedZone("Europe/Rome", 2*60*60),
		logger: logger,
	}

	request := httptest.NewRequest(http.MethodGet, "/export.xlsx?from=2026-07-01&to=2026-07-31&issuetype=Task&user=andrea", nil)
	response := httptest.NewRecorder()
	app.handleExportExcel(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := response.Header().Get("Content-Disposition"); !strings.Contains(got, "Jira_Worklog_2026-07-01_2026-07-31.xlsx") {
		t.Errorf("Content-Disposition = %q", got)
	}

	book, err := excelize.OpenReader(bytes.NewReader(response.Body.Bytes()))
	if err != nil {
		t.Fatalf("download is not a valid workbook: %v", err)
	}
	t.Cleanup(func() { _ = book.Close() })
	if got, want := book.GetSheetList(), []string{"Riepilogo", "Andrea Faraone"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("sheet list = %v, want %v", got, want)
	}
	rows, err := book.GetRows("Andrea Faraone")
	if err != nil {
		t.Fatalf("read exported user sheet: %v", err)
	}
	contents := ""
	for _, row := range rows {
		contents += strings.Join(row, "|") + "\n"
	}
	for _, expected := range []string{"TL-1", "Task esportato", "Analisi export", "1.50 h", "8.00 h"} {
		if !strings.Contains(contents, expected) {
			t.Errorf("exported workbook does not contain %q", expected)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
