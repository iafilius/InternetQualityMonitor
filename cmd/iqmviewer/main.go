package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	png "image/png"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	fyne "fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	chart "github.com/wcharczuk/go-chart/v2"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

type uiState struct {
	app      fyne.App
	window   fyne.Window
	filePath string

	situation  string
	batchesN   int
	situations []string
	summaries  []analysis.BatchSummary

	// toggles and modes
	xAxisMode   string // "batch", "run_tag", or "time" (batch only for now)
	yScaleMode  string // "absolute" or "relative"
	showOverall bool
	showIPv4    bool
	showIPv6    bool

	// widgets
	table          *widget.Table
	batchesLabel   *widget.Label
	speedImgCanvas *canvas.Image
	ttfbImgCanvas  *canvas.Image

	// prefs
	speedUnit string // "kbps", "kBps", "Mbps", "MBps", "Gbps", "GBps"
}

// speedUnitNameAndFactor converts from base kbps to the chosen unit
func speedUnitNameAndFactor(unit string) (string, float64) {
	switch unit {
	case "kbps":
		return "kbps", 1.0
	case "kBps":
		return "kBps", 1.0 / 8.0
	case "Mbps":
		return "Mbps", 1.0 / 1000.0
	case "MBps":
		return "MBps", 1.0 / 8000.0
	case "Gbps":
		return "Gbps", 1.0 / 1_000_000.0
	case "GBps":
		return "GBps", 1.0 / 8_000_000.0
	default:
		return "kbps", 1.0
	}
}

// dark theme wrapper
type darkTheme struct{}

func (d *darkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}
func (d *darkTheme) Font(style fyne.TextStyle) fyne.Resource { return theme.DefaultTheme().Font(style) }
func (d *darkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}
func (d *darkTheme) Size(name fyne.ThemeSizeName) float32 { return theme.DefaultTheme().Size(name) }

func main() {
	// CLI flags for opening a file directly
	var fileFlag string
	flag.StringVar(&fileFlag, "file", "", "Path to monitor_results.jsonl")
	flag.Parse()

	a := app.NewWithID("com.iqm.viewer")
	a.Settings().SetTheme(&darkTheme{})
	w := a.NewWindow("IQM Viewer")
	w.Resize(fyne.NewSize(1100, 800))

	state := &uiState{
		app:         a,
		window:      w,
		filePath:    fileFlag,
		batchesN:    50,
		xAxisMode:   "batch",
		yScaleMode:  "absolute",
		showOverall: true,
		showIPv4:    true,
		showIPv6:    true,
		speedUnit:   "kbps",
	}

	// top bar controls
	fileLabel := widget.NewLabel(truncatePath(state.filePath, 60))
	speedSelect := widget.NewSelect([]string{"kbps", "kBps", "Mbps", "MBps", "Gbps", "GBps"}, func(v string) {
		state.speedUnit = v
		savePrefs(state)
		// refresh table headers/values and charts to reflect unit change
		if state.table != nil {
			state.table.Refresh()
		}
		redrawCharts(state)
	})
	speedSelect.Selected = state.speedUnit

	// series toggles (callbacks assigned later, after canvases exist)
	overallChk := widget.NewCheck("Overall", nil)
	ipv4Chk := widget.NewCheck("IPv4", nil)
	ipv6Chk := widget.NewCheck("IPv6", nil)

	// axis mode selectors
	xAxisSelect := widget.NewSelect([]string{"Batch", "RunTag", "Time"}, func(v string) {
		switch strings.ToLower(v) {
		case "batch":
			state.xAxisMode = "batch"
		case "runtag", "run_tag":
			state.xAxisMode = "run_tag"
		case "time":
			state.xAxisMode = "time"
		}
		savePrefs(state)
		redrawCharts(state)
	})
	switch state.xAxisMode {
	case "run_tag":
		xAxisSelect.Selected = "RunTag"
	case "time":
		xAxisSelect.Selected = "Time"
	default:
		xAxisSelect.Selected = "Batch"
	}
	yScaleSelect := widget.NewSelect([]string{"Absolute", "Relative"}, func(v string) {
		if strings.ToLower(v) == "relative" {
			state.yScaleMode = "relative"
		} else {
			state.yScaleMode = "absolute"
		}
		savePrefs(state)
		redrawCharts(state)
	})
	if strings.EqualFold(state.yScaleMode, "relative") {
		yScaleSelect.Selected = "Relative"
	} else {
		yScaleSelect.Selected = "Absolute"
	}

	// Data table (batches overview)
	state.table = widget.NewTable(
		// size provider: 1 header row + data rows; 9 columns
		func() (int, int) {
			rows := len(filteredSummaries(state)) + 1
			if rows < 1 {
				rows = 1
			}
			return rows, 9
		},
		// template object
		func() fyne.CanvasObject { return widget.NewLabel("") },
		// cell update
		func(id widget.TableCellID, o fyne.CanvasObject) {
			lbl := o.(*widget.Label)
			rows := filteredSummaries(state)
			// columns: 0 RunTag, 1 Lines, 2 AvgSpeed, 3 AvgTTFB, 4 Errors, 5 v4 speed, 6 v4 ttfb, 7 v6 speed, 8 v6 ttfb
			if id.Row == 0 {
				unitName, _ := speedUnitNameAndFactor(state.speedUnit)
				switch id.Col {
				case 0:
					lbl.SetText("RunTag")
				case 1:
					lbl.SetText("Lines")
				case 2:
					lbl.SetText("Avg Speed (" + unitName + ")")
				case 3:
					lbl.SetText("Avg TTFB (ms)")
				case 4:
					lbl.SetText("Errors")
				case 5:
					lbl.SetText("IPv4 Speed (" + unitName + ")")
				case 6:
					lbl.SetText("IPv4 TTFB (ms)")
				case 7:
					lbl.SetText("IPv6 Speed (" + unitName + ")")
				case 8:
					lbl.SetText("IPv6 TTFB (ms)")
				}
				return
			}
			rix := id.Row - 1
			if rix < 0 || rix >= len(rows) {
				lbl.SetText("")
				return
			}
			_, factor := speedUnitNameAndFactor(state.speedUnit)
			bs := rows[rix]
			switch id.Col {
			case 0:
				lbl.SetText(bs.RunTag)
			case 1:
				lbl.SetText(fmt.Sprintf("%d", bs.Lines))
			case 2:
				lbl.SetText(fmt.Sprintf("%.1f", bs.AvgSpeed*factor))
			case 3:
				lbl.SetText(fmt.Sprintf("%.0f", bs.AvgTTFB))
			case 4:
				lbl.SetText(fmt.Sprintf("%d", bs.ErrorLines))
			case 5:
				if bs.IPv4 != nil {
					lbl.SetText(fmt.Sprintf("%.1f", bs.IPv4.AvgSpeed*factor))
				} else {
					lbl.SetText("-")
				}
			case 6:
				if bs.IPv4 != nil {
					lbl.SetText(fmt.Sprintf("%.0f", bs.IPv4.AvgTTFB))
				} else {
					lbl.SetText("-")
				}
			case 7:
				if bs.IPv6 != nil {
					lbl.SetText(fmt.Sprintf("%.1f", bs.IPv6.AvgSpeed*factor))
				} else {
					lbl.SetText("-")
				}
			case 8:
				if bs.IPv6 != nil {
					lbl.SetText(fmt.Sprintf("%.0f", bs.IPv6.AvgTTFB))
				} else {
					lbl.SetText("-")
				}
			}
		},
	)
	// initial column widths
	state.table.SetColumnWidth(0, 220)
	state.table.SetColumnWidth(1, 70)
	state.table.SetColumnWidth(2, 130)
	state.table.SetColumnWidth(3, 100)
	state.table.SetColumnWidth(4, 70)
	state.table.SetColumnWidth(5, 120)
	state.table.SetColumnWidth(6, 110)
	state.table.SetColumnWidth(7, 120)
	state.table.SetColumnWidth(8, 110)

	// chart placeholders
	state.speedImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.speedImgCanvas.FillMode = canvas.ImageFillContain
	state.ttfbImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.ttfbImgCanvas.FillMode = canvas.ImageFillContain

	// layout
	// top bar
	top := container.NewHBox(
		widget.NewButton("Open…", func() { openFileDialog(state, fileLabel) }),
		widget.NewButton("Reload", func() { loadAll(state, fileLabel) }),
		widget.NewLabel("Speed Unit:"), speedSelect,
		widget.NewLabel("X-Axis:"), xAxisSelect,
		widget.NewLabel("Y-Scale:"), yScaleSelect,
		overallChk, ipv4Chk, ipv6Chk,
		widget.NewLabel("File:"), fileLabel,
	)
	charts := container.NewHSplit(state.speedImgCanvas, state.ttfbImgCanvas)
	charts.Offset = 0.5
	// tabs: Batches | Charts
	tabs := container.NewAppTabs(
		container.NewTabItem("Batches", state.table),
		container.NewTabItem("Charts", charts),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	// persist selected tab on change
	tabs.OnSelected = func(ti *container.TabItem) {
		if state != nil && state.app != nil {
			state.app.Preferences().SetInt("selectedTabIndex", tabs.SelectedIndex())
		}
	}
	content := container.NewBorder(top, nil, nil, nil, tabs)
	w.SetContent(content)

	// Now that canvases are ready, assign checkbox callbacks
	overallChk.OnChanged = func(b bool) {
		state.showOverall = b
		savePrefs(state)
		updateColumnVisibility(state)
		redrawCharts(state)
	}
	ipv4Chk.OnChanged = func(b bool) { state.showIPv4 = b; savePrefs(state); updateColumnVisibility(state); redrawCharts(state) }
	ipv6Chk.OnChanged = func(b bool) { state.showIPv6 = b; savePrefs(state); updateColumnVisibility(state); redrawCharts(state) }

	// menus, prefs, initial load
	buildMenus(state, fileLabel)
	loadPrefs(state, overallChk, ipv4Chk, ipv6Chk, fileLabel, xAxisSelect, yScaleSelect, tabs, speedSelect)
	// Set initial checkbox states explicitly now that callbacks exist
	overallChk.SetChecked(state.showOverall)
	ipv4Chk.SetChecked(state.showIPv4)
	ipv6Chk.SetChecked(state.showIPv6)
	// Always load data once at startup (will fallback to monitor_results.jsonl if available)
	loadAll(state, fileLabel)

	w.ShowAndRun()
}

// menus and dialogs
func buildMenus(state *uiState, fileLabel *widget.Label) {
	if state == nil || state.window == nil || state.app == nil {
		return
	}
	var items []*fyne.MenuItem
	for _, f := range recentFiles(state) {
		f := f
		items = append(items, fyne.NewMenuItem(truncatePath(f, 60), func() {
			state.filePath = f
			fileLabel.SetText(truncatePath(state.filePath, 60))
			savePrefs(state)
			loadAll(state, fileLabel)
		}))
	}
	clearRecent := fyne.NewMenuItem("Clear Recent", func() { clearRecentFiles(state); buildMenus(state, fileLabel) })
	recentMenu := fyne.NewMenu("Open Recent", append(items, clearRecent)...)
	exportSpeed := fyne.NewMenuItem("Export Speed Chart…", func() { exportChartPNG(state, state.speedImgCanvas, "speed_chart.png") })
	exportTTFB := fyne.NewMenuItem("Export TTFB Chart…", func() { exportChartPNG(state, state.ttfbImgCanvas, "ttfb_chart.png") })
	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Open…", func() { openFileDialog(state, fileLabel) }),
		fyne.NewMenuItem("Reload", func() { loadAll(state, fileLabel) }),
		fyne.NewMenuItemSeparator(),
		exportSpeed,
		exportTTFB,
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() { state.window.Close() }),
	)
	mainMenu := fyne.NewMainMenu(fileMenu, recentMenu)
	state.window.SetMainMenu(mainMenu)

	canv := state.window.Canvas()
	if canv != nil {
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyO, Modifier: fyne.KeyModifierSuper}, func(fyne.Shortcut) { openFileDialog(state, fileLabel) })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyO, Modifier: fyne.KeyModifierControl}, func(fyne.Shortcut) { openFileDialog(state, fileLabel) })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyR, Modifier: fyne.KeyModifierSuper}, func(fyne.Shortcut) { loadAll(state, fileLabel) })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyR, Modifier: fyne.KeyModifierControl}, func(fyne.Shortcut) { loadAll(state, fileLabel) })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyW, Modifier: fyne.KeyModifierSuper}, func(fyne.Shortcut) { state.window.Close() })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyW, Modifier: fyne.KeyModifierControl}, func(fyne.Shortcut) { state.window.Close() })
	}
}

// file open dialog
func openFileDialog(state *uiState, fileLabel *widget.Label) {
	d := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil || rc == nil {
			return
		}
		defer rc.Close()
		state.filePath = rc.URI().Path()
		fileLabel.SetText(truncatePath(state.filePath, 60))
		addRecentFile(state, state.filePath)
		savePrefs(state)
		loadAll(state, fileLabel)
	}, state.window)
	d.Show()
}

// load data and render
func loadAll(state *uiState, fileLabel *widget.Label) {
	if state.filePath == "" {
		if _, err := os.Stat("monitor_results.jsonl"); err == nil {
			state.filePath = "monitor_results.jsonl"
			if fileLabel != nil {
				fileLabel.SetText(truncatePath(state.filePath, 60))
			}
		} else {
			return
		}
	}
	summaries, err := analysis.AnalyzeRecentResultsFull(state.filePath, monitor.SchemaVersion, state.batchesN, "")
	if err != nil {
		dialog.ShowError(err, state.window)
		return
	}
	state.summaries = summaries
	state.situations = uniqueSituations(summaries)
	if state.situation == "" && len(state.situations) > 0 {
		state.situation = state.situations[0]
	}
	if state.table != nil {
		state.table.Refresh()
	}
	updateColumnVisibility(state)
	redrawCharts(state)
}

func uniqueSituations(in []analysis.BatchSummary) []string {
	m := map[string]struct{}{}
	for _, s := range in {
		if s.Situation != "" {
			m[s.Situation] = struct{}{}
		}
	}
	arr := make([]string, 0, len(m))
	for k := range m {
		arr = append(arr, k)
	}
	sort.Strings(arr)
	return arr
}

func filteredSummaries(state *uiState) []analysis.BatchSummary {
	if state.situation == "" {
		return state.summaries
	}
	out := make([]analysis.BatchSummary, 0, len(state.summaries))
	for _, s := range state.summaries {
		if s.Situation == state.situation {
			out = append(out, s)
		}
	}
	return out
}

func redrawCharts(state *uiState) {
	// Speed chart
	spImg := renderSpeedChart(state)
	if spImg != nil {
		state.speedImgCanvas.Image = spImg
		state.speedImgCanvas.Refresh()
	}
	ttImg := renderTTFBChart(state)
	if ttImg != nil {
		state.ttfbImgCanvas.Image = ttImg
		state.ttfbImgCanvas.Refresh()
	}
}

func renderSpeedChart(state *uiState) image.Image {
	unitName, factor := speedUnitNameAndFactor(state.speedUnit)
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	// build X axis according to mode
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	// collect series
	series := []chart.Series{}
	minY := math.MaxFloat64

	if state.showOverall {
		ys := make([]float64, len(rows))
		for i, r := range rows {
			v := r.AvgSpeed * factor
			ys[i] = v
			if v > 0 && v < minY {
				minY = v
			}
		}
		if timeMode {
			series = append(series, chart.TimeSeries{Name: "Overall", XValues: times, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorAlternateGray, StrokeWidth: 2.0, StrokeDashArray: []float64{5, 3}}})
		} else {
			series = append(series, chart.ContinuousSeries{Name: "Overall", XValues: xs, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorAlternateGray, StrokeWidth: 2.0, StrokeDashArray: []float64{5, 3}}})
		}
	}
	if state.showIPv4 {
		ys := make([]float64, len(rows))
		for i, r := range rows {
			v := 0.0
			if r.IPv4 != nil {
				v = r.IPv4.AvgSpeed * factor
			}
			ys[i] = v
			if v > 0 && v < minY {
				minY = v
			}
		}
		if timeMode {
			series = append(series, chart.TimeSeries{Name: "IPv4", XValues: times, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorBlue, StrokeWidth: 2.0}})
		} else {
			series = append(series, chart.ContinuousSeries{Name: "IPv4", XValues: xs, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorBlue, StrokeWidth: 2.0}})
		}
	}
	if state.showIPv6 {
		ys := make([]float64, len(rows))
		for i, r := range rows {
			v := 0.0
			if r.IPv6 != nil {
				v = r.IPv6.AvgSpeed * factor
			}
			ys[i] = v
			if v > 0 && v < minY {
				minY = v
			}
		}
		if timeMode {
			series = append(series, chart.TimeSeries{Name: "IPv6", XValues: times, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorGreen, StrokeWidth: 2.0}})
		} else {
			series = append(series, chart.ContinuousSeries{Name: "IPv6", XValues: xs, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorGreen, StrokeWidth: 2.0}})
		}
	}

	yMin := 0.0
	if strings.EqualFold(state.yScaleMode, "relative") && minY != math.MaxFloat64 {
		yMin = minY
	}
	ch := chart.Chart{
		Title:      fmt.Sprintf("Avg Speed (%s)%s", unitName, situationSuffix(state)),
		Background: chart.Style{Padding: chart.Box{Top: 20, Left: 20, Right: 20, Bottom: 20}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: unitName, Range: &chart.ContinuousRange{Min: yMin}},
		Series:     series,
	}
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}

	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return nil
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return nil
	}
	return img
}

func renderTTFBChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY := math.MaxFloat64

	if state.showOverall {
		ys := make([]float64, len(rows))
		for i, r := range rows {
			v := r.AvgTTFB
			ys[i] = v
			if v > 0 && v < minY {
				minY = v
			}
		}
		if timeMode {
			series = append(series, chart.TimeSeries{Name: "Overall", XValues: times, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorAlternateGray, StrokeWidth: 2.0, StrokeDashArray: []float64{5, 3}}})
		} else {
			series = append(series, chart.ContinuousSeries{Name: "Overall", XValues: xs, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorAlternateGray, StrokeWidth: 2.0, StrokeDashArray: []float64{5, 3}}})
		}
	}
	if state.showIPv4 {
		ys := make([]float64, len(rows))
		for i, r := range rows {
			v := 0.0
			if r.IPv4 != nil {
				v = r.IPv4.AvgTTFB
			}
			ys[i] = v
			if v > 0 && v < minY {
				minY = v
			}
		}
		if timeMode {
			series = append(series, chart.TimeSeries{Name: "IPv4", XValues: times, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorBlue, StrokeWidth: 2.0}})
		} else {
			series = append(series, chart.ContinuousSeries{Name: "IPv4", XValues: xs, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorBlue, StrokeWidth: 2.0}})
		}
	}
	if state.showIPv6 {
		ys := make([]float64, len(rows))
		for i, r := range rows {
			v := 0.0
			if r.IPv6 != nil {
				v = r.IPv6.AvgTTFB
			}
			ys[i] = v
			if v > 0 && v < minY {
				minY = v
			}
		}
		if timeMode {
			series = append(series, chart.TimeSeries{Name: "IPv6", XValues: times, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorGreen, StrokeWidth: 2.0}})
		} else {
			series = append(series, chart.ContinuousSeries{Name: "IPv6", XValues: xs, YValues: ys, Style: chart.Style{StrokeColor: chart.ColorGreen, StrokeWidth: 2.0}})
		}
	}

	yMin := 0.0
	if strings.EqualFold(state.yScaleMode, "relative") && minY != math.MaxFloat64 {
		yMin = minY
	}
	ch := chart.Chart{
		Title:      fmt.Sprintf("Avg TTFB (ms)%s", situationSuffix(state)),
		Background: chart.Style{Padding: chart.Box{Top: 20, Left: 20, Right: 20, Bottom: 20}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: "ms", Range: &chart.ContinuousRange{Min: yMin}},
		Series:     series,
	}
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}

	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return nil
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return nil
	}
	return img
}

// buildXAxis constructs X values and axis config based on the selected mode.
// Returns whether time mode is used, the time slice (if applicable), the float Xs otherwise, and the configured XAxis.
func buildXAxis(rows []analysis.BatchSummary, mode string) (bool, []time.Time, []float64, chart.XAxis) {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "time":
		ts := make([]time.Time, len(rows))
		for i, r := range rows {
			ts[i] = parseRunTagTime(r.RunTag)
		}
		xa := chart.XAxis{
			Name:           "Time",
			ValueFormatter: chart.TimeValueFormatterWithFormat("01-02 15:04:05"),
		}
		return true, ts, nil, xa
	case "run_tag":
		xs := make([]float64, len(rows))
		ticks := make([]chart.Tick, len(rows))
		for i, r := range rows {
			x := float64(i + 1)
			xs[i] = x
			ticks[i] = chart.Tick{Value: x, Label: r.RunTag}
		}
		xa := chart.XAxis{Name: "RunTag", Ticks: ticks}
		return false, nil, xs, xa
	default:
		xs := make([]float64, len(rows))
		for i := range rows {
			xs[i] = float64(i + 1)
		}
		xa := chart.XAxis{Name: "Batch"}
		return false, nil, xs, xa
	}
}

// parseRunTagTime attempts to parse a timestamp from run_tag formats like YYYYMMDD_HHMMSS[_suffix].
func parseRunTagTime(runTag string) time.Time {
	// find first token that looks like 8 digits '_' 6 digits
	// common format seen: 20250818_132613 or 20250818_132613_i1
	parts := strings.Split(runTag, "_")
	if len(parts) >= 2 && len(parts[0]) == 8 && len(parts[1]) >= 6 {
		base := parts[0] + "_" + parts[1][:6]
		if t, err := time.ParseInLocation("20060102_150405", base, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

func situationSuffix(state *uiState) string {
	if state.situation == "" {
		return ""
	}
	return " – " + state.situation
}

func blank(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// subtle background
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{R: 18, G: 18, B: 18, A: 255})
		}
	}
	return img
}

// export PNG
func exportChartPNG(state *uiState, img *canvas.Image, defaultName string) {
	if state == nil || state.window == nil || img == nil || img.Image == nil {
		dialog.ShowInformation("Export", "No chart to export.", state.window)
		return
	}
	fs := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
		if err != nil || wc == nil {
			return
		}
		defer wc.Close()
		_ = png.Encode(wc, img.Image)
	}, state.window)
	fs.SetFileName(defaultName)
	fs.Show()
}

// recent files helpers
func recentFiles(state *uiState) []string {
	prefs := state.app.Preferences()
	raw := prefs.StringWithFallback("recentFiles", "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}
func addRecentFile(state *uiState, path string) {
	prefs := state.app.Preferences()
	list := recentFiles(state)
	filtered := []string{path}
	for _, f := range list {
		if f != path && len(filtered) < 10 {
			filtered = append(filtered, f)
		}
	}
	prefs.SetString("recentFiles", strings.Join(filtered, "\n"))
}
func clearRecentFiles(state *uiState) {
	if state == nil || state.app == nil {
		return
	}
	state.app.Preferences().SetString("recentFiles", "")
}

// prefs
func savePrefs(state *uiState) {
	if state == nil || state.app == nil {
		return
	}
	prefs := state.app.Preferences()
	prefs.SetString("lastFile", state.filePath)
	prefs.SetString("lastSituation", state.situation)
	prefs.SetInt("batchesN", state.batchesN)
	prefs.SetBool("showOverall", state.showOverall)
	prefs.SetBool("showIPv4", state.showIPv4)
	prefs.SetBool("showIPv6", state.showIPv6)
	prefs.SetString("xAxisMode", state.xAxisMode)
	prefs.SetString("yScaleMode", state.yScaleMode)
	prefs.SetString("speedUnit", state.speedUnit)
}

func loadPrefs(state *uiState, avg *widget.Check, v4 *widget.Check, v6 *widget.Check, fileLabel *widget.Label, xAxis *widget.Select, yScale *widget.Select, tabs *container.AppTabs, speedUnitSel *widget.Select) {
	if state == nil || state.app == nil {
		return
	}
	prefs := state.app.Preferences()
	if f := prefs.StringWithFallback("lastFile", state.filePath); f != "" {
		state.filePath = f
		if fileLabel != nil {
			fileLabel.SetText(truncatePath(state.filePath, 60))
		}
	}
	if n := prefs.IntWithFallback("batchesN", state.batchesN); n > 0 {
		state.batchesN = n
		if state.batchesLabel != nil {
			state.batchesLabel.SetText(fmt.Sprintf("%d", n))
		}
	}
	state.showOverall = prefs.BoolWithFallback("showOverall", state.showOverall)
	state.showIPv4 = prefs.BoolWithFallback("showIPv4", state.showIPv4)
	state.showIPv6 = prefs.BoolWithFallback("showIPv6", state.showIPv6)
	if avg != nil {
		avg.SetChecked(state.showOverall)
	}
	if v4 != nil {
		v4.SetChecked(state.showIPv4)
	}
	if v6 != nil {
		v6.SetChecked(state.showIPv6)
	}
	state.situation = prefs.StringWithFallback("lastSituation", state.situation)
	mode := prefs.StringWithFallback("xAxisMode", state.xAxisMode)
	switch mode {
	case "batch", "run_tag", "time":
		state.xAxisMode = mode
	}
	if xAxis != nil {
		switch state.xAxisMode {
		case "run_tag":
			xAxis.Selected = "RunTag"
		case "time":
			xAxis.Selected = "Time"
		default:
			xAxis.Selected = "Batch"
		}
	}
	ymode := prefs.StringWithFallback("yScaleMode", state.yScaleMode)
	switch ymode {
	case "absolute", "relative":
		state.yScaleMode = ymode
	}
	if yScale != nil {
		if strings.EqualFold(state.yScaleMode, "relative") {
			yScale.Selected = "Relative"
		} else {
			yScale.Selected = "Absolute"
		}
	}
	if su := prefs.StringWithFallback("speedUnit", state.speedUnit); su != "" {
		state.speedUnit = su
	}
	if speedUnitSel != nil {
		speedUnitSel.Selected = state.speedUnit
	}
	if tabs != nil {
		idx := prefs.IntWithFallback("selectedTabIndex", 0)
		if idx >= 0 && idx < len(tabs.Items) {
			tabs.SelectIndex(idx)
		}
	}
}

// utils
func truncatePath(p string, n int) string {
	if len(p) <= n {
		return p
	}
	base := filepath.Base(p)
	if len(base)+4 >= n {
		return "..." + base
	}
	dir := filepath.Dir(p)
	left := n - len(base) - 4
	if left <= 0 {
		return "..." + base
	}
	if len(dir) > left {
		dir = dir[:left]
	}
	return dir + "/..." + base
}

// Hide/show IPv4/IPv6 columns according to toggles
func updateColumnVisibility(state *uiState) {
	// Columns: 0 RunTag, 1 Lines, 2 AvgSpeed, 3 AvgTTFB, 4 Errors, 5 v4 speed, 6 v4 ttfb, 7 v6 speed, 8 v6 ttfb
	// We can't truly hide columns in fyne.Table; set width to 0 for hidden columns
	if state == nil || state.table == nil {
		return
	}
	if state.showOverall {
		state.table.SetColumnWidth(2, 130)
		state.table.SetColumnWidth(3, 100)
	} else {
		state.table.SetColumnWidth(2, 0)
		state.table.SetColumnWidth(3, 0)
	}
	if state.showIPv4 {
		state.table.SetColumnWidth(5, 100)
		state.table.SetColumnWidth(6, 100)
	} else {
		state.table.SetColumnWidth(5, 0)
		state.table.SetColumnWidth(6, 0)
	}
	if state.showIPv6 {
		state.table.SetColumnWidth(7, 100)
		state.table.SetColumnWidth(8, 100)
	} else {
		state.table.SetColumnWidth(7, 0)
		state.table.SetColumnWidth(8, 0)
	}
	state.table.Refresh()
}
