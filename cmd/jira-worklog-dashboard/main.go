package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gghidoni/jira-worklog-dashboard/internal/jira"
	"github.com/gghidoni/jira-worklog-dashboard/internal/ui"
)

type Config struct {
	ListenAddr         string
	JiraBaseURL        string
	JiraEmail          string
	JiraAPIToken       string
	TZ                 string
	MaxRangeDays       int
	WorklogConcurrency int
	FixedProjectKey    string

	BasicAuthUser string
	BasicAuthPass string
}

func main() {
	cfg := loadConfig()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	loc, err := time.LoadLocation(cfg.TZ)
	if err != nil {
		logger.Error("invalid timezone", "tz", cfg.TZ, "err", err)
		os.Exit(1)
	}

	jiraClient := jira.NewClient(jira.Config{
		BaseURL:  cfg.JiraBaseURL,
		Email:    cfg.JiraEmail,
		APIToken: cfg.JiraAPIToken,
		Timeout:  45 * time.Second,
		Logger:   logger,
	})

	tmpl, err := parseTemplates()
	if err != nil {
		logger.Error("parse templates", "err", err)
		os.Exit(1)
	}

	app := &App{
		cfg:       cfg,
		jira:      jiraClient,
		templates: tmpl,
		tz:        loc,
		logger:    logger,
		metaCache: newMetaCache(10 * time.Minute),

		issueTypeIconCache: newIssueTypeIconCache(12 * time.Hour),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.handleIndex)
	mux.HandleFunc("GET /healthz", app.handleHealth)
	mux.HandleFunc("GET /static/{path...}", app.handleStatic)
	mux.HandleFunc("GET /issuetype-icon", app.handleIssueTypeIcon)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.withMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("listening", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr:         envString("LISTEN_ADDR", ":8080"),
		JiraBaseURL:        strings.TrimRight(envString("JIRA_BASE_URL", ""), "/"),
		JiraEmail:          envString("JIRA_EMAIL", ""),
		JiraAPIToken:       envString("JIRA_API_TOKEN", ""),
		TZ:                 envString("DASH_TZ", "Europe/Rome"),
		MaxRangeDays:       envInt("MAX_RANGE_DAYS", 90),
		WorklogConcurrency: envInt("WORKLOG_CONCURRENCY", 8),
		FixedProjectKey:    envString("FIXED_PROJECT_KEY", ""),
		BasicAuthUser:      envString("DASH_BASIC_AUTH_USER", ""),
		BasicAuthPass:      envString("DASH_BASIC_AUTH_PASS", ""),
	}
	if cfg.WorklogConcurrency < 1 {
		cfg.WorklogConcurrency = 1
	}
	if cfg.MaxRangeDays < 1 {
		cfg.MaxRangeDays = 1
	}
	return cfg
}

func envString(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

type App struct {
	cfg       Config
	jira      *jira.Client
	templates *template.Template
	tz        *time.Location
	logger    *slog.Logger
	metaCache *MetaCache

	issueTypeIconCache *IssueTypeIconCache

	userNameCache sync.Map // accountId -> displayName
}

func (a *App) handleIssueTypeIcon(w http.ResponseWriter, r *http.Request) {
	if len(validateConfig(a.cfg)) != 0 {
		http.Error(w, "jira not configured", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	if body, ct, ok := a.issueTypeIconCache.Get(id); ok {
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
		return
	}

	_, issueTypes, _ := a.metaCache.GetOrFetch(r.Context(), a.jira, a.cfg.FixedProjectKey)
	iconURL := ""
	for _, it := range issueTypes {
		if it.ID == id {
			iconURL = strings.TrimSpace(it.IconURL)
			break
		}
	}
	if iconURL == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	body, ct, err := a.jira.FetchURL(r.Context(), iconURL)
	if err != nil {
		http.Error(w, "icon fetch failed", http.StatusBadGateway)
		return
	}
	if ct == "" {
		ct = "image/png"
	}
	a.issueTypeIconCache.Set(id, body, ct)

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(body)
}

type IssueTypeIconCache struct {
	ttl time.Duration

	mu    sync.Mutex
	items map[string]cachedIcon
}

type cachedIcon struct {
	expiresAt   time.Time
	contentType string
	body        []byte
}

func newIssueTypeIconCache(ttl time.Duration) *IssueTypeIconCache {
	return &IssueTypeIconCache{ttl: ttl, items: map[string]cachedIcon{}}
}

func (c *IssueTypeIconCache) Get(id string) ([]byte, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[id]
	if !ok {
		return nil, "", false
	}
	if time.Now().After(it.expiresAt) {
		delete(c.items, id)
		return nil, "", false
	}
	return append([]byte(nil), it.body...), it.contentType, true
}

func (c *IssueTypeIconCache) Set(id string, body []byte, contentType string) {
	if len(body) == 0 {
		return
	}
	if len(body) > 1<<20 {
		return
	}
	c.mu.Lock()
	c.items[id] = cachedIcon{expiresAt: time.Now().Add(c.ttl), contentType: contentType, body: append([]byte(nil), body...)}
	c.mu.Unlock()
}

func (a *App) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if a.cfg.BasicAuthUser != "" || a.cfg.BasicAuthPass != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(a.cfg.BasicAuthUser)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(a.cfg.BasicAuthPass)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="jira-worklog-dashboard"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
		a.logger.Info("request", "method", r.Method, "path", r.URL.Path, "dur", time.Since(start).String())
	})
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (a *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	name = path.Clean(name)
	name = strings.TrimPrefix(name, "/")
	if name == "" || name == "." || strings.HasPrefix(name, "..") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	b, err := ui.FS.ReadFile("static/" + name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ct := mime.TypeByExtension(path.Ext(name))
	if ct == "" {
		ct = http.DetectContentType(b)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

type Filters struct {
	From string
	To   string

	BoardID string

	Projects   []string
	IssueTypes []string
	Users      []string // accountIds

	Run bool
}

type PageData struct {
	Title string

	ConfigOK       bool
	ConfigProblems []string

	Filters          Filters
	FixedProjectKey  string
	Projects         []jira.Project
	IssueTypes       []jira.IssueType
	Boards           []jira.Board
	AvailableUsers   []UserOption
	AvailableUserCnt int

	Errors   []string
	Warnings []string

	TotalSeconds int64
	TotalHuman   string

	Table Table
	Stats QueryStats
}

type UserOption struct {
	AccountID   string
	DisplayName string
}

type Cell struct {
	Text string
	Href string

	IconSrc string
	IconAlt string
}

type Table struct {
	Columns []string
	Rows    []TableRow
}

type TableRow struct {
	Cells []Cell
}

type QueryStats struct {
	Issues   int
	Worklogs int
	Users    int
	Duration string
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filters := parseFilters(r, a.tz)
	if a.cfg.FixedProjectKey != "" {
		filters.Projects = []string{a.cfg.FixedProjectKey}
	}
	cfgProblems := validateConfig(a.cfg)
	cfgOK := len(cfgProblems) == 0

	data := PageData{
		Title:           "Jira Worklog Dashboard",
		ConfigOK:        cfgOK,
		ConfigProblems:  cfgProblems,
		Filters:         filters,
		FixedProjectKey: a.cfg.FixedProjectKey,
	}

	// Load metadata for select inputs (best-effort).
	if cfgOK {
		projects, issueTypes, boards := a.metaCache.GetOrFetch(ctx, a.jira, a.cfg.FixedProjectKey)
		data.Projects = projects
		data.IssueTypes = issueTypes
		data.Boards = boards
	}

	// Auto-run by default (dashboard behavior). Use run=0 to only render the form.
	if r.URL.Query().Get("run") == "0" {
		data.Filters.Run = false
		a.render(w, "index.html", data)
		return
	}
	if !cfgOK {
		data.Errors = append(data.Errors, "Missing Jira configuration (set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN)")
		a.render(w, "index.html", data)
		return
	}

	// Validate date range.
	fromDate, toDate, errs := parseDateRange(filters.From, filters.To, a.tz, a.cfg.MaxRangeDays)
	if len(errs) > 0 {
		data.Errors = append(data.Errors, errs...)
		a.render(w, "index.html", data)
		return
	}

	startedAfter, startedBefore := epochRangeInclusive(fromDate, toDate)

	jql, jqlWarnings := buildJQL(filters, fromDate, toDate)
	data.Warnings = append(data.Warnings, jqlWarnings...)

	start := time.Now()
	var (
		issues     []jira.Issue
		searchWarn []string
		err        error
	)
	if filters.BoardID != "" {
		boardID, err2 := strconv.Atoi(filters.BoardID)
		if err2 != nil {
			data.Errors = append(data.Errors, "Invalid board id")
			a.render(w, "index.html", data)
			return
		}
		issues, searchWarn, err = a.jira.BoardIssues(ctx, boardID, jira.BoardIssuesRequest{
			JQL:               jql,
			Fields:            []string{"summary", "project", "issuetype"},
			MaxResultsPerPage: 100,
		})
	} else {
		issues, searchWarn, err = a.jira.SearchIssues(ctx, jira.SearchIssuesRequest{
			JQL:               jql,
			Fields:            []string{"summary", "project", "issuetype"},
			MaxResultsPerPage: 100,
		})
	}
	if err != nil {
		data.Errors = append(data.Errors, fmt.Sprintf("Jira search failed: %v", err))
		a.render(w, "index.html", data)
		return
	}
	data.Warnings = append(data.Warnings, searchWarn...)

	worklogsAll, wlWarn, err := fetchWorklogs(ctx, a.jira, issues, startedAfter, startedBefore, a.cfg.WorklogConcurrency)
	if err != nil {
		data.Errors = append(data.Errors, fmt.Sprintf("Worklog fetch failed: %v", err))
		a.render(w, "index.html", data)
		return
	}
	data.Warnings = append(data.Warnings, wlWarn...)

	availableUsers := buildAvailableUsers(worklogsAll)
	availableUsers = ensureUsersPresent(availableUsers, filters.Users)
	availableUsers = hydrateUserOptions(ctx, a.jira, &a.userNameCache, availableUsers)
	data.AvailableUsers = availableUsers
	data.AvailableUserCnt = len(buildAvailableUsers(worklogsAll))

	worklogs := filterWorklogsByUsers(worklogsAll, filters.Users)

	totalSeconds := int64(0)
	for _, wl := range worklogs {
		totalSeconds += int64(wl.TimeSpentSeconds)
	}
	data.TotalSeconds = totalSeconds
	data.TotalHuman = humanDurationSeconds(totalSeconds)
	data.Stats = QueryStats{Issues: len(issues), Worklogs: len(worklogs), Users: len(buildAvailableUsers(worklogs)), Duration: time.Since(start).Truncate(10 * time.Millisecond).String()}
	data.Table = buildTable(a.cfg.JiraBaseURL, worklogs)

	a.render(w, "index.html", data)
}

func (a *App) render(w http.ResponseWriter, name string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.ExecuteTemplate(w, name, data); err != nil {
		a.logger.Error("template render", "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

func validateConfig(cfg Config) []string {
	var probs []string
	if cfg.JiraBaseURL == "" {
		probs = append(probs, "JIRA_BASE_URL is missing")
	}
	if cfg.JiraEmail == "" {
		probs = append(probs, "JIRA_EMAIL is missing")
	}
	if cfg.JiraAPIToken == "" {
		probs = append(probs, "JIRA_API_TOKEN is missing")
	}
	return probs
}

func parseTemplates() (*template.Template, error) {
	funcMap := template.FuncMap{
		"join": strings.Join,
		"itoa": strconv.Itoa,
		"contains": func(list []string, v string) bool {
			for _, it := range list {
				if it == v {
					return true
				}
			}
			return false
		},
	}

	t := template.New("root").Funcs(funcMap)
	return t.ParseFS(ui.FS, "templates/index.html")
}

func parseFilters(r *http.Request, loc *time.Location) Filters {
	q := r.URL.Query()

	// Defaults: last 7 days.
	today := time.Now().In(loc)
	defTo := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, loc)
	defFrom := defTo.AddDate(0, 0, -6)

	from := strings.TrimSpace(q.Get("from"))
	to := strings.TrimSpace(q.Get("to"))
	if from == "" {
		from = defFrom.Format("2006-01-02")
	}
	if to == "" {
		to = defTo.Format("2006-01-02")
	}

	filters := Filters{
		From:       from,
		To:         to,
		BoardID:    strings.TrimSpace(q.Get("board")),
		Projects:   parseMulti(q, "project"),
		IssueTypes: parseMulti(q, "issuetype"),
		Users:      parseMulti(q, "user"),
		Run:        q.Get("run") == "1",
	}
	return filters
}

func parseMulti(q map[string][]string, key string) []string {
	raw := q[key]
	var out []string
	seen := map[string]struct{}{}
	for _, v := range raw {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ok := seen[part]; ok {
				continue
			}
			seen[part] = struct{}{}
			out = append(out, part)
		}
	}
	sort.Strings(out)
	return out
}

func parseDateRange(fromStr, toStr string, loc *time.Location, maxRangeDays int) (time.Time, time.Time, []string) {
	var errs []string
	from, err := time.ParseInLocation("2006-01-02", fromStr, loc)
	if err != nil {
		errs = append(errs, "Invalid from date (expected YYYY-MM-DD)")
	}
	to, err := time.ParseInLocation("2006-01-02", toStr, loc)
	if err != nil {
		errs = append(errs, "Invalid to date (expected YYYY-MM-DD)")
	}
	if len(errs) > 0 {
		return time.Time{}, time.Time{}, errs
	}
	if to.Before(from) {
		return time.Time{}, time.Time{}, []string{"Invalid date range (to < from)"}
	}
	// Count whole calendar days (DST-safe).
	days := 1
	for d := from; d.Before(to); d = d.AddDate(0, 0, 1) {
		days++
		if days > maxRangeDays {
			break
		}
	}
	if days > maxRangeDays {
		return time.Time{}, time.Time{}, []string{fmt.Sprintf("Date range too large (%d days). Max is %d days.", days, maxRangeDays)}
	}
	return from, to, nil
}

func epochRangeInclusive(fromDate, toDate time.Time) (startedAfterMs, startedBeforeMs int64) {
	// Inclusive of both endpoints.
	start := time.Date(fromDate.Year(), fromDate.Month(), fromDate.Day(), 0, 0, 0, 0, fromDate.Location())
	endExclusive := time.Date(toDate.Year(), toDate.Month(), toDate.Day(), 0, 0, 0, 0, toDate.Location()).AddDate(0, 0, 1)
	end := endExclusive.Add(-1 * time.Millisecond)
	return start.UnixMilli(), end.UnixMilli()
}

func buildJQL(f Filters, fromDate, toDate time.Time) (string, []string) {
	var parts []string
	parts = append(parts, fmt.Sprintf("worklogDate >= \"%s\"", fromDate.Format("2006-01-02")))
	parts = append(parts, fmt.Sprintf("worklogDate <= \"%s\"", toDate.Format("2006-01-02")))

	if len(f.Projects) > 0 {
		// project keys are typically safe unquoted, but we quote defensively.
		parts = append(parts, fmt.Sprintf("project in (%s)", joinJQLStrings(f.Projects)))
	}
	if len(f.IssueTypes) > 0 {
		parts = append(parts, fmt.Sprintf("issuetype in (%s)", joinJQLStrings(f.IssueTypes)))
	}

	return strings.Join(parts, " AND "), nil
}

func joinJQLStrings(values []string) string {
	var out []string
	for _, v := range values {
		out = append(out, quoteJQLString(v))
	}
	return strings.Join(out, ", ")
}

func quoteJQLString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

type WorklogItem struct {
	IssueKey          string
	IssueSummary      string
	ProjectKey        string
	ProjectName       string
	IssueType         string
	IssueTypeID       string
	AuthorAccountID   string
	AuthorDisplayName string
	TimeSpentSeconds  int
}

func fetchWorklogs(
	ctx context.Context,
	c *jira.Client,
	issues []jira.Issue,
	startedAfterMs, startedBeforeMs int64,
	concurrency int,
) ([]WorklogItem, []string, error) {
	if len(issues) == 0 {
		return nil, nil, nil
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	var mu sync.Mutex
	var out []WorklogItem
	var warns []string
	var firstErr error

	for _, iss := range issues {
		if ctx.Err() != nil {
			break
		}
		iss := iss
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			wls, err := c.GetIssueWorklogs(ctx, iss.Key, jira.GetIssueWorklogsRequest{
				StartedAfterMs:    startedAfterMs,
				StartedBeforeMs:   startedBeforeMs,
				MaxResultsPerPage: 100,
			})
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}

			var items []WorklogItem
			for _, wl := range wls {
				if wl.TimeSpentSeconds <= 0 {
					continue
				}
				items = append(items, WorklogItem{
					IssueKey:          iss.Key,
					IssueSummary:      iss.Fields.Summary,
					ProjectKey:        iss.Fields.Project.Key,
					ProjectName:       iss.Fields.Project.Name,
					IssueType:         iss.Fields.IssueType.Name,
					IssueTypeID:       iss.Fields.IssueType.ID,
					AuthorAccountID:   wl.Author.AccountID,
					AuthorDisplayName: wl.Author.DisplayName,
					TimeSpentSeconds:  wl.TimeSpentSeconds,
				})
			}

			mu.Lock()
			out = append(out, items...)
			mu.Unlock()
		}()
	}

	wg.Wait()
	if firstErr != nil {
		return nil, warns, firstErr
	}
	return out, warns, nil
}

func buildAvailableUsers(items []WorklogItem) []UserOption {
	m := map[string]string{}
	for _, it := range items {
		if it.AuthorAccountID == "" {
			continue
		}
		name := strings.TrimSpace(it.AuthorDisplayName)
		if existing, ok := m[it.AuthorAccountID]; ok {
			// Prefer a non-empty display name if we see one.
			if existing != "" {
				continue
			}
		}
		m[it.AuthorAccountID] = name
	}
	out := make([]UserOption, 0, len(m))
	for id, name := range m {
		out = append(out, UserOption{AccountID: id, DisplayName: name})
	}
	sort.Slice(out, func(i, j int) bool {
		li := strings.ToLower(displayOrID(out[i]))
		lj := strings.ToLower(displayOrID(out[j]))
		if li == lj {
			return out[i].AccountID < out[j].AccountID
		}
		return li < lj
	})
	return out
}

func ensureUsersPresent(options []UserOption, selected []string) []UserOption {
	seen := map[string]struct{}{}
	for _, o := range options {
		seen[o.AccountID] = struct{}{}
	}
	for _, id := range selected {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		options = append(options, UserOption{AccountID: id})
		seen[id] = struct{}{}
	}
	sort.Slice(options, func(i, j int) bool {
		li := strings.ToLower(displayOrID(options[i]))
		lj := strings.ToLower(displayOrID(options[j]))
		if li == lj {
			return options[i].AccountID < options[j].AccountID
		}
		return li < lj
	})
	return options
}

func hydrateUserOptions(ctx context.Context, jiraClient *jira.Client, cache *sync.Map, options []UserOption) []UserOption {
	for i := range options {
		if strings.TrimSpace(options[i].DisplayName) != "" {
			continue
		}
		id := strings.TrimSpace(options[i].AccountID)
		if id == "" {
			continue
		}
		if v, ok := cache.Load(id); ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				options[i].DisplayName = s
				continue
			}
		}
		user, err := jiraClient.GetUser(ctx, id)
		if err == nil {
			name := strings.TrimSpace(user.DisplayName)
			if name != "" {
				options[i].DisplayName = name
				cache.Store(id, name)
				continue
			}
		}
		// Last resort: show accountId.
		options[i].DisplayName = id
		cache.Store(id, id)
	}
	return options
}

func displayOrID(u UserOption) string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return u.DisplayName
	}
	return u.AccountID
}

func filterWorklogsByUsers(items []WorklogItem, users []string) []WorklogItem {
	if len(users) == 0 {
		return items
	}
	allowed := map[string]struct{}{}
	for _, u := range users {
		if u == "" {
			continue
		}
		allowed[u] = struct{}{}
	}
	if len(allowed) == 0 {
		return items
	}
	out := make([]WorklogItem, 0, len(items))
	for _, it := range items {
		if _, ok := allowed[it.AuthorAccountID]; ok {
			out = append(out, it)
		}
	}
	return out
}

func buildTable(jiraBaseURL string, items []WorklogItem) Table {
	type agg struct {
		issueKey     string
		summary      string
		issueType    string
		issueTypeID  string
		secondsTotal int64
	}
	m := map[string]*agg{}

	for _, it := range items {
		key := it.IssueKey
		a := m[key]
		if a == nil {
			a = &agg{issueKey: it.IssueKey, summary: it.IssueSummary, issueType: it.IssueType, issueTypeID: it.IssueTypeID}
			m[key] = a
		}
		a.secondsTotal += int64(it.TimeSpentSeconds)
	}

	type row struct {
		cells   []Cell
		seconds int64
	}
	rows := make([]row, 0, len(m))
	for _, a := range m {
		href := strings.TrimRight(jiraBaseURL, "/") + "/browse/" + a.issueKey
		iconSrc := ""
		if strings.TrimSpace(a.issueTypeID) != "" {
			iconSrc = "/issuetype-icon?id=" + url.QueryEscape(a.issueTypeID)
		}
		rows = append(rows, row{cells: []Cell{{Text: a.issueKey, Href: href, IconSrc: iconSrc, IconAlt: a.issueType}, {Text: a.summary}, {Text: a.issueType}, {Text: humanDurationSeconds(a.secondsTotal)}}, seconds: a.secondsTotal})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].seconds == rows[j].seconds {
			// Secondary: issue key.
			return rows[i].cells[0].Text < rows[j].cells[0].Text
		}
		return rows[i].seconds > rows[j].seconds
	})

	table := Table{}
	table.Columns = []string{"Issue", "Summary", "Issue Type", "Total"}

	for _, r := range rows {
		table.Rows = append(table.Rows, TableRow{Cells: r.cells})
	}
	return table
}

func humanDurationSeconds(seconds int64) string {
	if seconds <= 0 {
		return "0m"
	}
	mins := (seconds + 30) / 60
	h := mins / 60
	m := mins % 60
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}

// ---- metadata cache ----

type MetaCache struct {
	ttl time.Duration

	mu         sync.Mutex
	expiresAt  time.Time
	projects   []jira.Project
	issueTypes []jira.IssueType
	boards     []jira.Board
}

func newMetaCache(ttl time.Duration) *MetaCache {
	return &MetaCache{ttl: ttl}
}

func (c *MetaCache) GetOrFetch(ctx context.Context, jiraClient *jira.Client, projectKey string) ([]jira.Project, []jira.IssueType, []jira.Board) {
	c.mu.Lock()
	if time.Now().Before(c.expiresAt) && (len(c.projects) > 0 || len(c.issueTypes) > 0 || len(c.boards) > 0) {
		p := append([]jira.Project(nil), c.projects...)
		it := append([]jira.IssueType(nil), c.issueTypes...)
		b := append([]jira.Board(nil), c.boards...)
		c.mu.Unlock()
		return p, it, b
	}
	c.mu.Unlock()

	// Best effort; no hard failure.
	projects, _ := jiraClient.ProjectSearch(ctx)
	issueTypes, _ := jiraClient.IssueTypes(ctx)
	var boards []jira.Board
	if strings.TrimSpace(projectKey) != "" {
		boards, _ = jiraClient.Boards(ctx, projectKey)
	}

	c.mu.Lock()
	c.projects = projects
	c.issueTypes = issueTypes
	c.boards = boards
	c.expiresAt = time.Now().Add(c.ttl)
	p := append([]jira.Project(nil), c.projects...)
	it := append([]jira.IssueType(nil), c.issueTypes...)
	b := append([]jira.Board(nil), c.boards...)
	c.mu.Unlock()
	return p, it, b
}
