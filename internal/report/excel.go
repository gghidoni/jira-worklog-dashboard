package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xuri/excelize/v2"
)

type Worklog struct {
	IssueKey          string
	IssueSummary      string
	IssueURL          string
	EstimateSeconds   int64
	Started           string
	Comment           string
	AuthorAccountID   string
	AuthorDisplayName string
	TimeSpentSeconds  int
}

type Options struct {
	From     time.Time
	To       time.Time
	Location *time.Location
}

type userGroup struct {
	AccountID string
	Name      string
	SheetName string
	Worklogs  []Worklog
}

type taskGroup struct {
	Key             string
	Summary         string
	URL             string
	EstimateSeconds int64
	Worklogs        []Worklog
}

type workbookStyles struct {
	title, subtitle, note, section, header int
	body, bodyAlt, date, hours             int
	task, taskLink, taskHours              int
	kpiLabel, kpiValue, kpiHours           int
	total, totalHours                      int
}

const (
	summarySheet = "Riepilogo"
	tableRow     = 8
)

func BuildExcel(opts Options, worklogs []Worklog) ([]byte, error) {
	if opts.Location == nil {
		opts.Location = time.UTC
	}
	users := groupByUser(worklogs)
	months := reportMonths(opts.From, opts.To)

	f := excelize.NewFile()
	defer f.Close()
	f.SetSheetName("Sheet1", summarySheet)

	styles, err := newWorkbookStyles(f)
	if err != nil {
		return nil, err
	}
	if err := buildSummary(f, styles, opts, users, months, len(worklogs)); err != nil {
		return nil, err
	}
	for _, user := range users {
		if _, err := f.NewSheet(user.SheetName); err != nil {
			return nil, fmt.Errorf("create user sheet: %w", err)
		}
		if err := buildUserSheet(f, styles, opts, user, months); err != nil {
			return nil, err
		}
	}
	f.SetActiveSheet(0)

	var output bytes.Buffer
	if err := f.Write(&output); err != nil {
		return nil, fmt.Errorf("write xlsx: %w", err)
	}
	return output.Bytes(), nil
}

func groupByUser(worklogs []Worklog) []userGroup {
	byID := map[string]*userGroup{}
	for _, worklog := range worklogs {
		id := strings.TrimSpace(worklog.AuthorAccountID)
		if id == "" {
			id = strings.TrimSpace(worklog.AuthorDisplayName)
		}
		user := byID[id]
		if user == nil {
			name := strings.TrimSpace(worklog.AuthorDisplayName)
			if name == "" {
				name = id
			}
			user = &userGroup{AccountID: id, Name: name}
			byID[id] = user
		}
		user.Worklogs = append(user.Worklogs, worklog)
	}
	users := make([]userGroup, 0, len(byID))
	for _, user := range byID {
		users = append(users, *user)
	}
	sort.Slice(users, func(i, j int) bool {
		if strings.EqualFold(users[i].Name, users[j].Name) {
			return users[i].AccountID < users[j].AccountID
		}
		return strings.ToLower(users[i].Name) < strings.ToLower(users[j].Name)
	})
	used := map[string]bool{strings.ToLower(summarySheet): true}
	for i := range users {
		users[i].SheetName = uniqueSheetName(users[i].Name, used)
	}
	return users
}

func reportMonths(from, to time.Time) []time.Time {
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return nil
	}
	current := time.Date(from.Year(), from.Month(), 1, 0, 0, 0, 0, from.Location())
	last := time.Date(to.Year(), to.Month(), 1, 0, 0, 0, 0, to.Location())
	var months []time.Time
	for !current.After(last) {
		months = append(months, current)
		current = current.AddDate(0, 1, 0)
	}
	return months
}

func buildSummary(f *excelize.File, styles workbookStyles, opts Options, users []userGroup, months []time.Time, worklogCount int) error {
	if err := setupSummaryColumns(f, len(months)); err != nil {
		return err
	}
	lastColumn := max(8, len(months)+2)
	lastColumnName, _ := excelize.ColumnNumberToName(lastColumn)
	if err := f.MergeCell(summarySheet, "A1", lastColumnName+"1"); err != nil {
		return err
	}
	if err := f.MergeCell(summarySheet, "A2", lastColumnName+"2"); err != nil {
		return err
	}
	if err := f.MergeCell(summarySheet, "A3", lastColumnName+"3"); err != nil {
		return err
	}
	setStyledValue(f, summarySheet, "A1", "Jira Worklog Report", styles.title)
	setStyledValue(f, summarySheet, "A2", fmt.Sprintf("%s – %s · dettaglio per utente · tempi in ore", opts.From.Format("02/01/2006"), opts.To.Format("02/01/2006")), styles.subtitle)
	setStyledValue(f, summarySheet, "A3", "I filtri della dashboard determinano intervallo, board, tipi di task e utenti inclusi.", styles.note)

	totalSeconds := totalWorklogSeconds(flattenUsers(users))
	setStyledValue(f, summarySheet, "A5", "UTENTI", styles.kpiLabel)
	setStyledValue(f, summarySheet, "C5", "WORKLOG", styles.kpiLabel)
	setStyledValue(f, summarySheet, "E5", "TEMPO TOTALE", styles.kpiLabel)
	setStyledValue(f, summarySheet, "A6", len(users), styles.kpiValue)
	setStyledValue(f, summarySheet, "C6", worklogCount, styles.kpiValue)
	setStyledValue(f, summarySheet, "E6", hours(totalSeconds), styles.kpiHours)

	headers := []any{"Utente"}
	for _, month := range months {
		headers = append(headers, monthLabel(month))
	}
	headers = append(headers, "Totale")
	if err := setRow(f, summarySheet, tableRow, headers, styles.header); err != nil {
		return err
	}

	for userIndex, user := range users {
		row := tableRow + 1 + userIndex
		style := styles.body
		if userIndex%2 == 1 {
			style = styles.bodyAlt
		}
		setStyledValue(f, summarySheet, cell(1, row), user.Name, style)
		userTotal := 0
		for monthIndex, month := range months {
			seconds := monthSeconds(user.Worklogs, month, opts.Location)
			userTotal += seconds
			setStyledValue(f, summarySheet, cell(monthIndex+2, row), hours(seconds), styles.hours)
		}
		setStyledValue(f, summarySheet, cell(len(months)+2, row), hours(userTotal), styles.hours)
	}

	totalRow := tableRow + 1 + len(users)
	setStyledValue(f, summarySheet, cell(1, totalRow), "Totale complessivo", styles.total)
	for monthIndex, month := range months {
		setStyledValue(f, summarySheet, cell(monthIndex+2, totalRow), hours(monthSeconds(flattenUsers(users), month, opts.Location)), styles.totalHours)
	}
	setStyledValue(f, summarySheet, cell(len(months)+2, totalRow), hours(totalSeconds), styles.totalHours)

	lastTableColumn := len(months) + 2
	if err := f.AutoFilter(summarySheet, fmt.Sprintf("A%d:%s%d", tableRow, mustColumn(lastTableColumn), totalRow), nil); err != nil {
		return err
	}
	if err := f.SetPanes(summarySheet, &excelize.Panes{Freeze: true, YSplit: tableRow, TopLeftCell: fmt.Sprintf("A%d", tableRow+1), ActivePane: "bottomLeft"}); err != nil {
		return err
	}
	if len(users) > 0 && len(months) > 0 {
		if err := addSummaryChart(f, users, months); err != nil {
			return err
		}
	}
	return nil
}

func setupSummaryColumns(f *excelize.File, monthCount int) error {
	if err := f.SetColWidth(summarySheet, "A", "A", 28); err != nil {
		return err
	}
	for column := 2; column <= monthCount+2; column++ {
		name := mustColumn(column)
		if err := f.SetColWidth(summarySheet, name, name, 17); err != nil {
			return err
		}
	}
	return nil
}

func addSummaryChart(f *excelize.File, users []userGroup, months []time.Time) error {
	firstRow := tableRow + 1
	lastRow := tableRow + len(users)
	series := make([]excelize.ChartSeries, 0, len(months))
	for index := range months {
		column := mustColumn(index + 2)
		series = append(series, excelize.ChartSeries{
			Name:       fmt.Sprintf("%s!$%s$%d", summarySheet, column, tableRow),
			Categories: fmt.Sprintf("%s!$A$%d:$A$%d", summarySheet, firstRow, lastRow),
			Values:     fmt.Sprintf("%s!$%s$%d:$%s$%d", summarySheet, column, firstRow, column, lastRow),
		})
	}
	show := true
	return f.AddChart(summarySheet, cell(len(months)+4, 5), &excelize.Chart{
		Type:      excelize.Col,
		Series:    series,
		Format:    excelize.GraphicOptions{PrintObject: &show},
		Dimension: excelize.ChartDimension{Width: 650, Height: 360},
		Title:     []excelize.RichTextRun{{Text: "Ore per utente e mese"}},
		Legend:    excelize.ChartLegend{Position: "bottom"},
		YAxis:     excelize.ChartAxis{NumFmt: excelize.ChartNumFmt{CustomNumFmt: `0.00 "h"`}},
	})
}

func buildUserSheet(f *excelize.File, styles workbookStyles, opts Options, user userGroup, months []time.Time) error {
	sheet := user.SheetName
	for column, width := range map[string]float64{"A": 15, "B": 14, "C": 17, "D": 39, "E": 52, "F": 17, "G": 17} {
		if err := f.SetColWidth(sheet, column, column, width); err != nil {
			return err
		}
	}
	for _, merge := range [][2]string{{"A1", "G1"}, {"A2", "G2"}, {"A3", "G3"}} {
		if err := f.MergeCell(sheet, merge[0], merge[1]); err != nil {
			return err
		}
	}
	setStyledValue(f, sheet, "A1", "Worklog · "+user.Name, styles.title)
	setStyledValue(f, sheet, "A2", fmt.Sprintf("%s – %s · tempi in ore", opts.From.Format("02/01/2006"), opts.To.Format("02/01/2006")), styles.subtitle)
	setStyledValue(f, sheet, "A3", "Le sottorighe mostrano solo i worklog descritti; quelli senza descrizione sono raggruppati e omessi quando sono gli unici presenti.", styles.note)
	distinctTasks := map[string]struct{}{}
	for _, worklog := range user.Worklogs {
		distinctTasks[worklog.IssueKey] = struct{}{}
	}
	setStyledValue(f, sheet, "A5", "WORKLOG", styles.kpiLabel)
	setStyledValue(f, sheet, "C5", "TASK DISTINTI", styles.kpiLabel)
	setStyledValue(f, sheet, "E5", "TEMPO TOTALE", styles.kpiLabel)
	setStyledValue(f, sheet, "A6", len(user.Worklogs), styles.kpiValue)
	setStyledValue(f, sheet, "C6", len(distinctTasks), styles.kpiValue)
	setStyledValue(f, sheet, "E6", hours(totalWorklogSeconds(user.Worklogs)), styles.kpiHours)

	headers := []any{"Tipo riga", "Data / mese", "Codice task", "Titolo task", "Descrizione worklog", "Tempo stimato", "Tempo totale"}
	if err := setRow(f, sheet, tableRow, headers, styles.header); err != nil {
		return err
	}
	row := tableRow + 1
	for monthIndex := len(months) - 1; monthIndex >= 0; monthIndex-- {
		month := months[monthIndex]
		groups := taskGroupsForMonth(user.Worklogs, month, opts.Location)
		if len(groups) == 0 {
			continue
		}
		if err := f.MergeCell(sheet, cell(1, row), cell(7, row)); err != nil {
			return err
		}
		setStyledValue(f, sheet, cell(1, row), monthLabel(month), styles.section)
		row++
		for _, group := range groups {
			total := totalWorklogSeconds(group.Worklogs)
			setStyledValue(f, sheet, cell(1, row), "TASK", styles.task)
			setStyledValue(f, sheet, cell(2, row), monthLabel(month), styles.task)
			setStyledValue(f, sheet, cell(3, row), group.Key, styles.taskLink)
			if group.URL != "" {
				if err := f.SetCellHyperLink(sheet, cell(3, row), group.URL, "External"); err != nil {
					return err
				}
			}
			setStyledValue(f, sheet, cell(4, row), group.Summary, styles.task)
			setStyledValue(f, sheet, cell(5, row), fmt.Sprintf("%d worklog", len(group.Worklogs)), styles.task)
			setStyledValue(f, sheet, cell(6, row), hours64(group.EstimateSeconds), styles.taskHours)
			setStyledValue(f, sheet, cell(7, row), hours(total), styles.taskHours)
			row++

			described, undescribedCount, undescribedSeconds := splitDescriptions(group.Worklogs)
			for _, worklog := range described {
				started := parseStarted(worklog.Started, opts.Location)
				setStyledValue(f, sheet, cell(1, row), "↳ Worklog", styles.bodyAlt)
				setStyledValue(f, sheet, cell(2, row), started, styles.date)
				setStyledValue(f, sheet, cell(5, row), strings.TrimSpace(worklog.Comment), styles.bodyAlt)
				setStyledValue(f, sheet, cell(7, row), hours(worklog.TimeSpentSeconds), styles.hours)
				_ = f.SetRowOutlineLevel(sheet, row, 1)
				row++
			}
			if len(described) > 0 && undescribedCount > 0 {
				setStyledValue(f, sheet, cell(1, row), "↳ Worklog", styles.bodyAlt)
				setStyledValue(f, sheet, cell(5, row), fmt.Sprintf("Worklog senza descrizione (%d)", undescribedCount), styles.bodyAlt)
				setStyledValue(f, sheet, cell(7, row), hours(undescribedSeconds), styles.hours)
				_ = f.SetRowOutlineLevel(sheet, row, 1)
				row++
			}
		}
	}
	lastRow := max(tableRow, row-1)
	if err := f.AutoFilter(sheet, fmt.Sprintf("A%d:G%d", tableRow, lastRow), nil); err != nil {
		return err
	}
	return f.SetPanes(sheet, &excelize.Panes{Freeze: true, YSplit: tableRow, TopLeftCell: fmt.Sprintf("A%d", tableRow+1), ActivePane: "bottomLeft"})
}

func taskGroupsForMonth(worklogs []Worklog, month time.Time, loc *time.Location) []taskGroup {
	groups := map[string]*taskGroup{}
	for _, worklog := range worklogs {
		started := parseStarted(worklog.Started, loc)
		if started.IsZero() || started.Year() != month.Year() || started.Month() != month.Month() {
			continue
		}
		group := groups[worklog.IssueKey]
		if group == nil {
			group = &taskGroup{Key: worklog.IssueKey, Summary: worklog.IssueSummary, URL: worklog.IssueURL, EstimateSeconds: worklog.EstimateSeconds}
			groups[worklog.IssueKey] = group
		}
		group.Worklogs = append(group.Worklogs, worklog)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]taskGroup, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		sort.Slice(group.Worklogs, func(i, j int) bool {
			return parseStarted(group.Worklogs[i].Started, loc).Before(parseStarted(group.Worklogs[j].Started, loc))
		})
		result = append(result, *group)
	}
	return result
}

func splitDescriptions(worklogs []Worklog) (described []Worklog, undescribedCount, undescribedSeconds int) {
	for _, worklog := range worklogs {
		if strings.TrimSpace(worklog.Comment) == "" {
			undescribedCount++
			undescribedSeconds += worklog.TimeSpentSeconds
			continue
		}
		described = append(described, worklog)
	}
	return described, undescribedCount, undescribedSeconds
}

func newWorkbookStyles(f *excelize.File) (workbookStyles, error) {
	var styles workbookStyles
	customHours := `0.00 "h"`
	border := []excelize.Border{{Type: "left", Color: "D5DEE5", Style: 1}, {Type: "top", Color: "D5DEE5", Style: 1}, {Type: "right", Color: "D5DEE5", Style: 1}, {Type: "bottom", Color: "D5DEE5", Style: 1}}
	definitions := []*excelize.Style{
		{Font: &excelize.Font{Bold: true, Size: 20, Color: "FFFFFF", Family: "Aptos Display"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"16324F"}, Pattern: 1}, Alignment: &excelize.Alignment{Vertical: "center"}},
		{Font: &excelize.Font{Bold: true, Size: 12, Color: "16324F", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"DCEAF3"}, Pattern: 1}},
		{Font: &excelize.Font{Size: 10, Color: "243447", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"DCEAF3"}, Pattern: 1}, Alignment: &excelize.Alignment{WrapText: true, Vertical: "center"}},
		{Font: &excelize.Font{Bold: true, Size: 10, Color: "16324F", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"CCE3F0"}, Pattern: 1}},
		{Font: &excelize.Font{Bold: true, Size: 10, Color: "FFFFFF", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"2A6F97"}, Pattern: 1}, Border: border, Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true}},
		{Font: &excelize.Font{Size: 10, Color: "243447", Family: "Aptos"}, Border: border, Alignment: &excelize.Alignment{Vertical: "center", WrapText: true}},
		{Font: &excelize.Font{Size: 10, Color: "243447", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"F6F9FB"}, Pattern: 1}, Border: border, Alignment: &excelize.Alignment{Vertical: "center", WrapText: true}},
		{Font: &excelize.Font{Size: 10, Color: "243447", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"F6F9FB"}, Pattern: 1}, Border: border, Alignment: &excelize.Alignment{Vertical: "center"}, CustomNumFmt: strptr("dd/mm/yyyy")},
		{Font: &excelize.Font{Size: 10, Color: "243447", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"F6F9FB"}, Pattern: 1}, Border: border, Alignment: &excelize.Alignment{Horizontal: "right", Vertical: "center"}, CustomNumFmt: &customHours},
		{Font: &excelize.Font{Bold: true, Size: 10, Color: "16324F", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"EAF2F7"}, Pattern: 1}, Border: border, Alignment: &excelize.Alignment{Vertical: "center", WrapText: true}},
		{Font: &excelize.Font{Bold: true, Underline: "single", Size: 10, Color: "0563C1", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"EAF2F7"}, Pattern: 1}, Border: border},
		{Font: &excelize.Font{Bold: true, Size: 10, Color: "16324F", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"EAF2F7"}, Pattern: 1}, Border: border, Alignment: &excelize.Alignment{Horizontal: "right"}, CustomNumFmt: &customHours},
		{Font: &excelize.Font{Bold: true, Size: 10, Color: "16324F", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"DCEAF3"}, Pattern: 1}, Border: border, Alignment: &excelize.Alignment{Horizontal: "center"}},
		{Font: &excelize.Font{Bold: true, Size: 12, Color: "16324F", Family: "Aptos"}, Border: border, Alignment: &excelize.Alignment{Horizontal: "center"}},
		{Font: &excelize.Font{Bold: true, Size: 12, Color: "16324F", Family: "Aptos"}, Border: border, Alignment: &excelize.Alignment{Horizontal: "center"}, CustomNumFmt: &customHours},
		{Font: &excelize.Font{Bold: true, Size: 10, Color: "16324F", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"CCE3F0"}, Pattern: 1}, Border: border},
		{Font: &excelize.Font{Bold: true, Size: 10, Color: "16324F", Family: "Aptos"}, Fill: excelize.Fill{Type: "pattern", Color: []string{"CCE3F0"}, Pattern: 1}, Border: border, Alignment: &excelize.Alignment{Horizontal: "right"}, CustomNumFmt: &customHours},
	}
	ids := make([]int, len(definitions))
	for index, definition := range definitions {
		id, err := f.NewStyle(definition)
		if err != nil {
			return styles, fmt.Errorf("create workbook style: %w", err)
		}
		ids[index] = id
	}
	styles = workbookStyles{title: ids[0], subtitle: ids[1], note: ids[2], section: ids[3], header: ids[4], body: ids[5], bodyAlt: ids[6], date: ids[7], hours: ids[8], task: ids[9], taskLink: ids[10], taskHours: ids[11], kpiLabel: ids[12], kpiValue: ids[13], kpiHours: ids[14], total: ids[15], totalHours: ids[16]}
	return styles, nil
}

func setStyledValue(f *excelize.File, sheet, coordinate string, value any, style int) {
	_ = f.SetCellValue(sheet, coordinate, value)
	_ = f.SetCellStyle(sheet, coordinate, coordinate, style)
}

func setRow(f *excelize.File, sheet string, row int, values []any, style int) error {
	for column, value := range values {
		coordinate := cell(column+1, row)
		if err := f.SetCellValue(sheet, coordinate, value); err != nil {
			return err
		}
		if err := f.SetCellStyle(sheet, coordinate, coordinate, style); err != nil {
			return err
		}
	}
	return nil
}

func flattenUsers(users []userGroup) []Worklog {
	var worklogs []Worklog
	for _, user := range users {
		worklogs = append(worklogs, user.Worklogs...)
	}
	return worklogs
}

func totalWorklogSeconds(worklogs []Worklog) int {
	total := 0
	for _, worklog := range worklogs {
		total += worklog.TimeSpentSeconds
	}
	return total
}

func monthSeconds(worklogs []Worklog, month time.Time, loc *time.Location) int {
	total := 0
	for _, worklog := range worklogs {
		started := parseStarted(worklog.Started, loc)
		if started.Year() == month.Year() && started.Month() == month.Month() {
			total += worklog.TimeSpentSeconds
		}
	}
	return total
}

func parseStarted(value string, loc *time.Location) time.Time {
	layouts := []string{time.RFC3339, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05.000Z0700"}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.In(loc)
		}
	}
	return time.Time{}
}

func monthLabel(month time.Time) string {
	names := [...]string{"Gennaio", "Febbraio", "Marzo", "Aprile", "Maggio", "Giugno", "Luglio", "Agosto", "Settembre", "Ottobre", "Novembre", "Dicembre"}
	return fmt.Sprintf("%s %d", names[month.Month()-1], month.Year())
}

func uniqueSheetName(name string, used map[string]bool) string {
	name = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`[]:*?/\\`, r) {
			return '-'
		}
		return r
	}, strings.TrimSpace(name))
	if name == "" {
		name = "Utente"
	}
	name = truncateRunes(name, 31)
	base := name
	for suffix := 2; used[strings.ToLower(name)]; suffix++ {
		tail := fmt.Sprintf(" (%d)", suffix)
		name = truncateRunes(base, 31-utf8.RuneCountInString(tail)) + tail
	}
	used[strings.ToLower(name)] = true
	return name
}

func truncateRunes(value string, maxLength int) string {
	runes := []rune(value)
	if len(runes) > maxLength {
		runes = runes[:maxLength]
	}
	return string(runes)
}

func hours(seconds int) float64     { return float64(seconds) / 3600 }
func hours64(seconds int64) float64 { return float64(seconds) / 3600 }
func cell(column, row int) string   { return fmt.Sprintf("%s%d", mustColumn(column), row) }
func mustColumn(column int) string  { name, _ := excelize.ColumnNumberToName(column); return name }
func strptr(value string) *string   { return &value }
func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
