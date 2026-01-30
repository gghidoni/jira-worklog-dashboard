package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BaseURL  string
	Email    string
	APIToken string
	Timeout  time.Duration
	Logger   *slog.Logger
}

type Client struct {
	baseURL string
	email   string
	token   string
	http    *http.Client
	logger  *slog.Logger
}

func NewClient(cfg Config) *Client {
	l := cfg.Logger
	if l == nil {
		l = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		email:   cfg.Email,
		token:   cfg.APIToken,
		http:    &http.Client{Timeout: timeout},
		logger:  l,
	}
}

type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("jira api error: status=%d", e.StatusCode)
	}
	body := e.Body
	if len(body) > 300 {
		body = body[:300] + "…"
	}
	return fmt.Sprintf("jira api error: status=%d body=%s", e.StatusCode, body)
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	if c.baseURL == "" {
		return errors.New("jira base url is empty")
	}
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return err
	}
	u = u.ResolveReference(ref)
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.email != "" || c.token != "" {
		req.SetBasicAuth(c.email, c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: string(b)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		// Helpful for debugging Jira's responses.
		c.logger.Debug("jira json unmarshal failed", "path", path, "err", err, "body", string(b))
		return err
	}
	return nil
}

func (c *Client) FetchURL(ctx context.Context, rawURL string) ([]byte, string, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, "", err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	if !strings.EqualFold(u.Hostname(), base.Hostname()) {
		return nil, "", fmt.Errorf("refusing cross-host fetch: %s", u.Hostname())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "*/*")
	if c.email != "" || c.token != "" {
		req.SetBasicAuth(c.email, c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", &APIError{StatusCode: resp.StatusCode, Body: string(b)}
	}
	ct := strings.TrimSpace(resp.Header.Get("Content-Type"))
	return b, ct, nil
}

// ---- data types ----

type Project struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

type IssueType struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IconURL string `json:"iconUrl"`
	Subtask bool   `json:"subtask"`
}

type Issue struct {
	ID     string      `json:"id"`
	Key    string      `json:"key"`
	Fields IssueFields `json:"fields"`
}

type IssueFields struct {
	Summary   string    `json:"summary"`
	Project   Project   `json:"project"`
	IssueType IssueType `json:"issuetype"`
}

type User struct {
	AccountID   string `json:"accountId"`
	DisplayName string `json:"displayName"`
}

type WorklogAuthor struct {
	AccountID   string `json:"accountId"`
	DisplayName string `json:"displayName"`
}

type Worklog struct {
	ID               string        `json:"id"`
	TimeSpentSeconds int           `json:"timeSpentSeconds"`
	Started          string        `json:"started"`
	Author           WorklogAuthor `json:"author"`
}

type Board struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// ---- API methods ----

func (c *Client) ProjectSearch(ctx context.Context) ([]Project, error) {
	// /rest/api/3/project/search is paginated.
	type page struct {
		IsLast     bool      `json:"isLast"`
		StartAt    int       `json:"startAt"`
		MaxResults int       `json:"maxResults"`
		Total      int       `json:"total"`
		Values     []Project `json:"values"`
		NextPage   string    `json:"nextPage"`
	}

	var out []Project
	startAt := 0
	for {
		q := url.Values{}
		q.Set("startAt", strconv.Itoa(startAt))
		q.Set("maxResults", "50")
		var p page
		if err := c.doJSON(ctx, http.MethodGet, "/rest/api/3/project/search", q, nil, &p); err != nil {
			return nil, err
		}
		out = append(out, p.Values...)
		if p.IsLast || len(p.Values) == 0 {
			break
		}
		startAt += len(p.Values)
		if startAt >= p.Total && p.Total != 0 {
			break
		}
	}
	// Sort by key.
	sortProjects(out)
	return out, nil
}

func sortProjects(ps []Project) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Key == ps[j].Key {
			return ps[i].Name < ps[j].Name
		}
		return ps[i].Key < ps[j].Key
	})
}

func (c *Client) IssueTypes(ctx context.Context) ([]IssueType, error) {
	var out []IssueType
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/3/issuetype", nil, nil, &out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func (c *Client) Boards(ctx context.Context, projectKeyOrID string) ([]Board, error) {
	// Jira Software (Agile) API.
	// /rest/agile/1.0/board is paginated.
	type page struct {
		StartAt    int     `json:"startAt"`
		MaxResults int     `json:"maxResults"`
		Total      int     `json:"total"`
		IsLast     bool    `json:"isLast"`
		Values     []Board `json:"values"`
	}

	var out []Board
	startAt := 0
	for {
		q := url.Values{}
		q.Set("startAt", strconv.Itoa(startAt))
		q.Set("maxResults", "50")
		q.Set("type", "kanban")
		if strings.TrimSpace(projectKeyOrID) != "" {
			q.Set("projectKeyOrId", strings.TrimSpace(projectKeyOrID))
		}

		var p page
		if err := c.doJSON(ctx, http.MethodGet, "/rest/agile/1.0/board", q, nil, &p); err != nil {
			return nil, err
		}
		out = append(out, p.Values...)
		if p.IsLast || len(p.Values) == 0 {
			break
		}
		startAt += len(p.Values)
		if startAt >= p.Total && p.Total != 0 {
			break
		}
	}

	sort.Slice(out, func(i, j int) bool {
		ni := strings.ToLower(out[i].Name)
		nj := strings.ToLower(out[j].Name)
		if ni == nj {
			return out[i].ID < out[j].ID
		}
		return ni < nj
	})
	return out, nil
}

type BoardIssuesRequest struct {
	JQL               string
	Fields            []string
	MaxResultsPerPage int
}

func (c *Client) BoardIssues(ctx context.Context, boardID int, req BoardIssuesRequest) ([]Issue, []string, error) {
	if req.MaxResultsPerPage <= 0 {
		req.MaxResultsPerPage = 100
	}
	// /rest/agile/1.0/board/{boardId}/issue is paginated.
	type resp struct {
		StartAt    int     `json:"startAt"`
		MaxResults int     `json:"maxResults"`
		Total      int     `json:"total"`
		Issues     []Issue `json:"issues"`
	}

	var out []Issue
	startAt := 0
	for {
		q := url.Values{}
		q.Set("startAt", strconv.Itoa(startAt))
		q.Set("maxResults", strconv.Itoa(req.MaxResultsPerPage))
		if strings.TrimSpace(req.JQL) != "" {
			q.Set("jql", req.JQL)
		}
		if len(req.Fields) > 0 {
			q.Set("fields", strings.Join(req.Fields, ","))
		}

		var r resp
		path := fmt.Sprintf("/rest/agile/1.0/board/%d/issue", boardID)
		if err := c.doJSON(ctx, http.MethodGet, path, q, nil, &r); err != nil {
			return nil, nil, err
		}
		out = append(out, r.Issues...)
		startAt += len(r.Issues)
		if len(r.Issues) == 0 || startAt >= r.Total {
			break
		}
	}
	return out, nil, nil
}

type SearchIssuesRequest struct {
	JQL               string
	Fields            []string
	MaxResultsPerPage int
}

func (c *Client) SearchIssues(ctx context.Context, req SearchIssuesRequest) ([]Issue, []string, error) {
	if req.MaxResultsPerPage <= 0 {
		req.MaxResultsPerPage = 100
	}
	// Prefer /search/jql (enhanced search). Fallback to /search if needed.
	issues, warns, err := c.searchIssuesEnhanced(ctx, req)
	if err == nil {
		return issues, warns, nil
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		warns = append(warns, "Jira did not support /rest/api/3/search/jql; fell back to /rest/api/3/search")
		issues2, err2 := c.searchIssuesLegacy(ctx, req)
		if err2 != nil {
			return nil, warns, err2
		}
		return issues2, warns, nil
	}

	// If JQL includes worklogAuthor and it fails, retry without it.
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest && strings.Contains(req.JQL, "worklogAuthor") {
		warns = append(warns, "Jira rejected worklogAuthor in JQL; retrying without it (user filter will be applied client-side)")
		req2 := req
		req2.JQL = stripWorklogAuthorClause(req2.JQL)
		issues2, warns2, err2 := c.searchIssuesEnhanced(ctx, req2)
		warns = append(warns, warns2...)
		if err2 == nil {
			return issues2, warns, nil
		}
		// Try legacy as last resort.
		issues3, err3 := c.searchIssuesLegacy(ctx, req2)
		if err3 == nil {
			warns = append(warns, "Fell back to /rest/api/3/search after JQL retry")
			return issues3, warns, nil
		}
		return nil, warns, err
	}
	return nil, warns, err
}

func stripWorklogAuthorClause(jql string) string {
	// Very small, defensive heuristic: remove any 'AND worklogAuthor = ...' segment.
	parts := strings.Split(jql, " AND ")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.Contains(p, "worklogAuthor") {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		return jql
	}
	return strings.Join(kept, " AND ")
}

func (c *Client) searchIssuesEnhanced(ctx context.Context, req SearchIssuesRequest) ([]Issue, []string, error) {
	type resp struct {
		IsLast        bool    `json:"isLast"`
		Issues        []Issue `json:"issues"`
		NextPageToken string  `json:"nextPageToken"`
		NextPage      string  `json:"nextPage"`
	}
	type body struct {
		JQL           string   `json:"jql"`
		MaxResults    int      `json:"maxResults"`
		NextPageToken string   `json:"nextPageToken,omitempty"`
		Fields        []string `json:"fields,omitempty"`
	}

	var warns []string
	var out []Issue
	next := ""
	for {
		b := body{JQL: req.JQL, MaxResults: req.MaxResultsPerPage, NextPageToken: next, Fields: req.Fields}
		var r resp
		if err := c.doJSON(ctx, http.MethodPost, "/rest/api/3/search/jql", nil, b, &r); err != nil {
			return nil, warns, err
		}
		out = append(out, r.Issues...)
		if r.IsLast {
			break
		}
		if r.NextPageToken != "" {
			next = r.NextPageToken
			continue
		}
		// Some variants only expose nextPage URL.
		if r.NextPage != "" {
			u, err := url.Parse(r.NextPage)
			if err == nil {
				next = u.Query().Get("nextPageToken")
				if next != "" {
					continue
				}
			}
		}
		warns = append(warns, "Jira returned non-last page without nextPageToken; stopping pagination")
		break
	}
	return out, warns, nil
}

func (c *Client) searchIssuesLegacy(ctx context.Context, req SearchIssuesRequest) ([]Issue, error) {
	type resp struct {
		StartAt    int     `json:"startAt"`
		MaxResults int     `json:"maxResults"`
		Total      int     `json:"total"`
		Issues     []Issue `json:"issues"`
	}

	var out []Issue
	startAt := 0
	for {
		q := url.Values{}
		q.Set("jql", req.JQL)
		q.Set("startAt", strconv.Itoa(startAt))
		q.Set("maxResults", strconv.Itoa(req.MaxResultsPerPage))
		if len(req.Fields) > 0 {
			q.Set("fields", strings.Join(req.Fields, ","))
		}
		var r resp
		if err := c.doJSON(ctx, http.MethodGet, "/rest/api/3/search", q, nil, &r); err != nil {
			return nil, err
		}
		out = append(out, r.Issues...)
		startAt += len(r.Issues)
		if len(r.Issues) == 0 || startAt >= r.Total {
			break
		}
	}
	return out, nil
}

type GetIssueWorklogsRequest struct {
	StartedAfterMs    int64
	StartedBeforeMs   int64
	MaxResultsPerPage int
}

func (c *Client) GetIssueWorklogs(ctx context.Context, issueKey string, req GetIssueWorklogsRequest) ([]Worklog, error) {
	if req.MaxResultsPerPage <= 0 {
		req.MaxResultsPerPage = 100
	}

	type resp struct {
		StartAt    int       `json:"startAt"`
		MaxResults int       `json:"maxResults"`
		Total      int       `json:"total"`
		Worklogs   []Worklog `json:"worklogs"`
	}

	var out []Worklog
	startAt := 0
	for {
		q := url.Values{}
		q.Set("startAt", strconv.Itoa(startAt))
		q.Set("maxResults", strconv.Itoa(req.MaxResultsPerPage))
		if req.StartedAfterMs > 0 {
			q.Set("startedAfter", strconv.FormatInt(req.StartedAfterMs, 10))
		}
		if req.StartedBeforeMs > 0 {
			q.Set("startedBefore", strconv.FormatInt(req.StartedBeforeMs, 10))
		}
		var r resp
		path := "/rest/api/3/issue/" + url.PathEscape(issueKey) + "/worklog"
		if err := c.doJSON(ctx, http.MethodGet, path, q, nil, &r); err != nil {
			return nil, err
		}
		out = append(out, r.Worklogs...)
		startAt += len(r.Worklogs)
		if len(r.Worklogs) == 0 || startAt >= r.Total {
			break
		}
	}
	return out, nil
}

func (c *Client) UserSearch(ctx context.Context, query string) ([]User, error) {
	q := url.Values{}
	q.Set("query", query)
	q.Set("maxResults", "20")
	var out []User
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/3/user/search", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetUser(ctx context.Context, accountID string) (User, error) {
	q := url.Values{}
	q.Set("accountId", accountID)
	var out User
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/3/user", q, nil, &out); err != nil {
		return User{}, err
	}
	return out, nil
}
