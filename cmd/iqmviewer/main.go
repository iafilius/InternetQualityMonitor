package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	png "image/png"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	"github.com/wcharczuk/go-chart/v2/drawing"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// pointStyle returns a style that renders points only (no connecting line)
func pointStyle(col drawing.Color) chart.Style {
	return chart.Style{
		StrokeWidth: 0,
		DotWidth:    4,
		DotColor:    col,
	}
}

type uiState struct {
	app      fyne.App
	window   fyne.Window
	filePath string

	situation  string
	batchesN   int
	situations []string
	summaries  []analysis.BatchSummary
	// mapping from run_tag to situation loaded from meta in results file
	runTagSituation map[string]string

	// toggles and modes
	xAxisMode   string // "batch", "run_tag", or "time" (batch only for now)
	yScaleMode  string // "absolute" or "relative"
	useRelative bool   // derived flag to avoid case/string mismatches
	showOverall bool
	showIPv4    bool
	showIPv6    bool
	// (removed: pctlFamily, pctlCompare)

	// widgets
	table        *widget.Table
	batchesLabel *widget.Label
	// situation selector (populated after data load)
	situationSelect    *widget.Select
	speedImgCanvas     *canvas.Image
	ttfbImgCanvas      *canvas.Image
	pctlOverallImg     *canvas.Image
	pctlIPv4Img        *canvas.Image
	pctlIPv6Img        *canvas.Image
	tpctlOverallImg    *canvas.Image
	tpctlIPv4Img       *canvas.Image
	tpctlIPv6Img       *canvas.Image
	errImgCanvas       *canvas.Image
	jitterImgCanvas    *canvas.Image
	covImgCanvas       *canvas.Image
	plCountImgCanvas   *canvas.Image
	plLongestImgCanvas *canvas.Image
	plStableImgCanvas  *canvas.Image
	cacheImgCanvas     *canvas.Image
	proxyImgCanvas     *canvas.Image
	warmCacheImgCanvas *canvas.Image

	// overlays for additional charts
	errOverlay       *crosshairOverlay
	jitterOverlay    *crosshairOverlay
	covOverlay       *crosshairOverlay
	plCountOverlay   *crosshairOverlay
	plLongestOverlay *crosshairOverlay
	plStableOverlay  *crosshairOverlay
	cacheOverlay     *crosshairOverlay
	proxyOverlay     *crosshairOverlay
	warmCacheOverlay *crosshairOverlay

	// containers
	pctlGrid *fyne.Container

	// crosshair
	crosshairEnabled   bool
	speedOverlay       *crosshairOverlay
	ttfbOverlay        *crosshairOverlay
	pctlOverallOverlay *crosshairOverlay
	pctlIPv4Overlay    *crosshairOverlay
	pctlIPv6Overlay    *crosshairOverlay
	tpctlOverallOverlay *crosshairOverlay
	tpctlIPv4Overlay    *crosshairOverlay
	tpctlIPv6Overlay    *crosshairOverlay
	lastSpeedPopup     *widget.PopUp
	lastTTFBPopup      *widget.PopUp

	// chart hints toggle
	showHints bool

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
	// Ensure crosshair preference is loaded before creating overlays/controls
	state.crosshairEnabled = a.Preferences().BoolWithFallback("crosshair", false)
	// Load showHints early so the checkbox reflects it on creation
	state.showHints = a.Preferences().BoolWithFallback("showHints", false)
	// (removed: pctlFamily/pctlCompare preferences)

	// top bar controls
	fileLabel := widget.NewLabel(truncatePath(state.filePath, 60))
	// Create selects without callbacks first; we'll wire them after canvases exist
	speedSelect := widget.NewSelect([]string{"kbps", "kBps", "Mbps", "MBps", "Gbps", "GBps"}, nil)
	speedSelect.Selected = state.speedUnit

	// series toggles (callbacks assigned later, after canvases exist)
	overallChk := widget.NewCheck("Overall", nil)
	ipv4Chk := widget.NewCheck("IPv4", nil)
	ipv6Chk := widget.NewCheck("IPv6", nil)
	crosshairChk := widget.NewCheck("Crosshair", nil)
	// initialize crosshair check from preloaded preference before wiring events
	crosshairChk.SetChecked(state.crosshairEnabled)

	// axis mode selectors
	xAxisSelect := widget.NewSelect([]string{"Batch", "RunTag", "Time"}, nil)
	switch state.xAxisMode {
	case "run_tag":
		xAxisSelect.Selected = "RunTag"
	case "time":
		xAxisSelect.Selected = "Time"
	default:
		xAxisSelect.Selected = "Batch"
	}
	yScaleSelect := widget.NewSelect([]string{"Absolute", "Relative"}, nil)

	// (removed: percentiles family selector)
	if state.useRelative {
		yScaleSelect.Selected = "Relative"
	} else {
		yScaleSelect.Selected = "Absolute"
	}

	// (removed: compare toggle)

	// hints toggle (callback assigned later, after canvases are created)
	hintsChk := widget.NewCheck("Hints", nil)
	hintsChk.SetChecked(state.showHints)

	// Situation selector (options filled after first load)
	sitSelect := widget.NewSelect([]string{}, func(v string) {
		if strings.EqualFold(v, "all") {
			state.situation = ""
		} else {
			state.situation = v
		}
		// small debug to verify selection behavior and filtered counts
		fmt.Printf("[viewer] situation changed to: %q; filtered batches=%d\n", v, len(filteredSummaries(state)))
		savePrefs(state)
		if state.table != nil {
			state.table.Refresh()
		}
		redrawCharts(state)
		// ensure overlays re-evaluate filtered data immediately
		if state.speedOverlay != nil {
			state.speedOverlay.Refresh()
		}
		if state.ttfbOverlay != nil {
			state.ttfbOverlay.Refresh()
		}
	})
	sitSelect.PlaceHolder = "All"
	state.situationSelect = sitSelect

	// Batches control: - [label] +
	state.batchesLabel = widget.NewLabel(fmt.Sprintf("%d", state.batchesN))
	decB := widget.NewButton("-", func() {
		n := state.batchesN - 10
		if n < 10 {
			n = 10
		}
		if n != state.batchesN {
			state.batchesN = n
			state.batchesLabel.SetText(fmt.Sprintf("%d", n))
			savePrefs(state)
			loadAll(state, fileLabel)
		}
	})
	incB := widget.NewButton("+", func() {
		n := state.batchesN + 10
		if n > 500 {
			n = 500
		}
		if n != state.batchesN {
			state.batchesN = n
			state.batchesLabel.SetText(fmt.Sprintf("%d", n))
			savePrefs(state)
			loadAll(state, fileLabel)
		}
	})

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
		widget.NewLabel("Situation:"), sitSelect,
		widget.NewLabel("Batches:"), decB, state.batchesLabel, incB,
		overallChk, ipv4Chk, ipv6Chk, crosshairChk, hintsChk,
		widget.NewLabel("File:"), fileLabel,
	)
	// charts stacked vertically with scroll for future additions
	// ensure reasonable minimum heights for readability
	state.speedImgCanvas.SetMinSize(fyne.NewSize(900, 320))
	state.ttfbImgCanvas.SetMinSize(fyne.NewSize(900, 320))
	// overlays for crosshair
	state.speedOverlay = newCrosshairOverlay(state, "speed")
	state.ttfbOverlay = newCrosshairOverlay(state, "ttfb")
	// new percentiles + error charts placeholders (stacked view only)
	// compare view canvases (vertical stack: Overall, IPv4, IPv6)
	state.pctlOverallImg = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.pctlOverallImg.FillMode = canvas.ImageFillContain
	state.pctlIPv4Img = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.pctlIPv4Img.FillMode = canvas.ImageFillContain
	state.pctlIPv6Img = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.pctlIPv6Img.FillMode = canvas.ImageFillContain
	// set initial min sizes to full chart size
	cw, chh := chartSize(state)
	state.pctlOverallImg.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
	state.pctlIPv4Img.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
	state.pctlIPv6Img.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
	// Create overlays for percentiles charts
	state.pctlOverallOverlay = newCrosshairOverlay(state, "pctl_overall")
	state.pctlIPv4Overlay = newCrosshairOverlay(state, "pctl_ipv4")
	state.pctlIPv6Overlay = newCrosshairOverlay(state, "pctl_ipv6")
	// TTFB percentile canvases
	state.tpctlOverallImg = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tpctlOverallImg.FillMode = canvas.ImageFillContain
	state.tpctlIPv4Img = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tpctlIPv4Img.FillMode = canvas.ImageFillContain
	state.tpctlIPv6Img = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tpctlIPv6Img.FillMode = canvas.ImageFillContain
	state.tpctlOverallImg.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
	state.tpctlIPv4Img.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
	state.tpctlIPv6Img.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
	// overlays for TTFB percentiles
	state.tpctlOverallOverlay = newCrosshairOverlay(state, "tpctl_overall")
	state.tpctlIPv4Overlay = newCrosshairOverlay(state, "tpctl_ipv4")
	state.tpctlIPv6Overlay = newCrosshairOverlay(state, "tpctl_ipv6")
	// Vertical stack with separators; put TTFB percentiles first so they follow Avg TTFB chart
	state.pctlGrid = container.NewVBox(
		container.NewStack(state.tpctlOverallImg, state.tpctlOverallOverlay),
		widget.NewSeparator(),
		container.NewStack(state.tpctlIPv4Img, state.tpctlIPv4Overlay),
		widget.NewSeparator(),
		container.NewStack(state.tpctlIPv6Img, state.tpctlIPv6Overlay),
		widget.NewSeparator(),
		container.NewStack(state.pctlOverallImg, state.pctlOverallOverlay),
		widget.NewSeparator(),
		container.NewStack(state.pctlIPv4Img, state.pctlIPv4Overlay),
		widget.NewSeparator(),
		container.NewStack(state.pctlIPv6Img, state.pctlIPv6Overlay),
	)
	state.errImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.errImgCanvas.FillMode = canvas.ImageFillContain
	state.errImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	// overlay for error rate
	state.errOverlay = newCrosshairOverlay(state, "error")
	// jitter & coefficient of variation charts
	state.jitterImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.jitterImgCanvas.FillMode = canvas.ImageFillContain
	state.jitterImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	state.jitterOverlay = newCrosshairOverlay(state, "jitter")
	state.covImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.covImgCanvas.FillMode = canvas.ImageFillContain
	state.covImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	state.covOverlay = newCrosshairOverlay(state, "cov")
	// plateau charts
	state.plCountImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.plCountImgCanvas.FillMode = canvas.ImageFillContain
	state.plCountImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	state.plCountOverlay = newCrosshairOverlay(state, "plateau_count")
	state.plLongestImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.plLongestImgCanvas.FillMode = canvas.ImageFillContain
	state.plLongestImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	state.plLongestOverlay = newCrosshairOverlay(state, "plateau_longest")
	// plateau stability rate chart
	state.plStableImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.plStableImgCanvas.FillMode = canvas.ImageFillContain
	state.plStableImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	state.plStableOverlay = newCrosshairOverlay(state, "plateau_stable")
	// cache/proxy/warm-cache rate charts
	state.cacheImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.cacheImgCanvas.FillMode = canvas.ImageFillContain
	state.cacheImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	state.cacheOverlay = newCrosshairOverlay(state, "cache_hit")
	state.proxyImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.proxyImgCanvas.FillMode = canvas.ImageFillContain
	state.proxyImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	state.proxyOverlay = newCrosshairOverlay(state, "proxy_suspected")
	state.warmCacheImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.warmCacheImgCanvas.FillMode = canvas.ImageFillContain
	state.warmCacheImgCanvas.SetMinSize(fyne.NewSize(900, 300))
	state.warmCacheOverlay = newCrosshairOverlay(state, "warm_cache")

	// charts column (hints are rendered inside chart images when enabled)
	chartsColumn := container.NewVBox(
		container.NewStack(state.speedImgCanvas, state.speedOverlay),
		widget.NewSeparator(),
		container.NewStack(state.ttfbImgCanvas, state.ttfbOverlay),
		widget.NewSeparator(),
		state.pctlGrid,
		widget.NewSeparator(),
		container.NewStack(state.errImgCanvas, state.errOverlay),
		widget.NewSeparator(),
		container.NewStack(state.jitterImgCanvas, state.jitterOverlay),
		widget.NewSeparator(),
		container.NewStack(state.covImgCanvas, state.covOverlay),
		widget.NewSeparator(),
		container.NewStack(state.cacheImgCanvas, state.cacheOverlay),
		widget.NewSeparator(),
		container.NewStack(state.proxyImgCanvas, state.proxyOverlay),
		widget.NewSeparator(),
		container.NewStack(state.warmCacheImgCanvas, state.warmCacheOverlay),
		widget.NewSeparator(),
		container.NewStack(state.plCountImgCanvas, state.plCountOverlay),
		widget.NewSeparator(),
		container.NewStack(state.plLongestImgCanvas, state.plLongestOverlay),
		widget.NewSeparator(),
		container.NewStack(state.plStableImgCanvas, state.plStableOverlay),
	)
	// Always show stacked percentiles
	state.pctlGrid.Show()
	chartsScroll := container.NewVScroll(chartsColumn)
	chartsScroll.SetMinSize(fyne.NewSize(900, 650))
	// tabs: Batches | Charts
	tabs := container.NewAppTabs(
		container.NewTabItem("Batches", state.table),
		container.NewTabItem("Charts", chartsScroll),
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

	// Redraw charts on window resize so they scale with width
	if w.Canvas() != nil {
		prevW := int(w.Canvas().Size().Width)
		done := make(chan struct{})
		w.SetOnClosed(func() {
			// ensure latest UI state (including crosshair) is persisted
			savePrefs(state)
			close(done)
		})
		go func() {
			t := time.NewTicker(300 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					c := w.Canvas()
					if c == nil {
						continue
					}
					sz := c.Size()
					curW := int(sz.Width)
					if curW != prevW {
						prevW = curW
						fyne.Do(func() { redrawCharts(state) })
					}
				}
			}
		}()
	}

	// Now that canvases are ready, assign checkbox callbacks
	overallChk.OnChanged = func(b bool) {
		state.showOverall = b
		savePrefs(state)
		updateColumnVisibility(state)
		redrawCharts(state)
	}

	// Wire select and hints callbacks after canvases exist
	speedSelect.OnChanged = func(v string) {
		state.speedUnit = v
		savePrefs(state)
		if state.table != nil {
			state.table.Refresh()
		}
		redrawCharts(state)
	}
	xAxisSelect.OnChanged = func(v string) {
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
	}
	yScaleSelect.OnChanged = func(v string) {
		if strings.EqualFold(v, "Relative") {
			state.yScaleMode = "relative"
			state.useRelative = true
		} else {
			state.yScaleMode = "absolute"
			state.useRelative = false
		}
		savePrefs(state)
		redrawCharts(state)
	}
	// (removed: pctlFamily/change and compare handlers)
	hintsChk.OnChanged = func(b bool) {
		state.showHints = b
		savePrefs(state)
		redrawCharts(state)
	}
	ipv4Chk.OnChanged = func(b bool) { state.showIPv4 = b; savePrefs(state); updateColumnVisibility(state); redrawCharts(state) }
	ipv6Chk.OnChanged = func(b bool) { state.showIPv6 = b; savePrefs(state); updateColumnVisibility(state); redrawCharts(state) }
	crosshairChk.OnChanged = func(b bool) {
		state.crosshairEnabled = b
		savePrefs(state)
		if state.speedOverlay != nil {
			state.speedOverlay.enabled = b
			state.speedOverlay.Refresh()
		}
		if state.ttfbOverlay != nil {
			state.ttfbOverlay.enabled = b
			state.ttfbOverlay.Refresh()
		}
		if state.pctlOverallOverlay != nil {
			state.pctlOverallOverlay.enabled = b
			state.pctlOverallOverlay.Refresh()
		}
		if state.pctlIPv4Overlay != nil {
			state.pctlIPv4Overlay.enabled = b
			state.pctlIPv4Overlay.Refresh()
		}
		if state.pctlIPv6Overlay != nil {
			state.pctlIPv6Overlay.enabled = b
			state.pctlIPv6Overlay.Refresh()
		}
		if state.errOverlay != nil {
			state.errOverlay.enabled = b
			state.errOverlay.Refresh()
		}
		if state.jitterOverlay != nil {
			state.jitterOverlay.enabled = b
			state.jitterOverlay.Refresh()
		}
		if state.covOverlay != nil {
			state.covOverlay.enabled = b
			state.covOverlay.Refresh()
		}
		if state.tpctlOverallOverlay != nil {
			state.tpctlOverallOverlay.enabled = b
			state.tpctlOverallOverlay.Refresh()
		}
		if state.tpctlIPv4Overlay != nil {
			state.tpctlIPv4Overlay.enabled = b
			state.tpctlIPv4Overlay.Refresh()
		}
		if state.tpctlIPv6Overlay != nil {
			state.tpctlIPv6Overlay.enabled = b
			state.tpctlIPv6Overlay.Refresh()
		}
		if state.plCountOverlay != nil {
			state.plCountOverlay.enabled = b
			state.plCountOverlay.Refresh()
		}
		if state.plLongestOverlay != nil {
			state.plLongestOverlay.enabled = b
			state.plLongestOverlay.Refresh()
		}
		if state.plStableOverlay != nil {
			state.plStableOverlay.enabled = b
			state.plStableOverlay.Refresh()
		}
		if state.cacheOverlay != nil {
			state.cacheOverlay.enabled = b
			state.cacheOverlay.Refresh()
		}
		if state.proxyOverlay != nil {
			state.proxyOverlay.enabled = b
			state.proxyOverlay.Refresh()
		}
		if state.warmCacheOverlay != nil {
			state.warmCacheOverlay.enabled = b
			state.warmCacheOverlay.Refresh()
		}
		if !b { // close popups
			if state.lastSpeedPopup != nil {
				state.lastSpeedPopup.Hide()
				state.lastSpeedPopup = nil
			}
			if state.lastTTFBPopup != nil {
				state.lastTTFBPopup.Hide()
				state.lastTTFBPopup = nil
			}
		}
	}

	// (removed duplicate wiring block)

	// menus, prefs, initial load
	buildMenus(state, fileLabel)
	loadPrefs(state, overallChk, ipv4Chk, ipv6Chk, fileLabel, xAxisSelect, yScaleSelect, tabs, speedSelect)
	// Set initial checkbox states explicitly now that callbacks exist
	overallChk.SetChecked(state.showOverall)
	ipv4Chk.SetChecked(state.showIPv4)
	ipv6Chk.SetChecked(state.showIPv6)
	crosshairChk.SetChecked(state.crosshairEnabled)
	// Ensure overlays reflect current preference immediately
	if state.speedOverlay != nil {
		state.speedOverlay.enabled = state.crosshairEnabled
		state.speedOverlay.Refresh()
	}
	if state.ttfbOverlay != nil {
		state.ttfbOverlay.enabled = state.crosshairEnabled
		state.ttfbOverlay.Refresh()
	}
	if state.errOverlay != nil {
		state.errOverlay.enabled = state.crosshairEnabled
		state.errOverlay.Refresh()
	}
	if state.tpctlOverallOverlay != nil {
		state.tpctlOverallOverlay.enabled = state.crosshairEnabled
		state.tpctlOverallOverlay.Refresh()
	}
	if state.tpctlIPv4Overlay != nil {
		state.tpctlIPv4Overlay.enabled = state.crosshairEnabled
		state.tpctlIPv4Overlay.Refresh()
	}
	if state.tpctlIPv6Overlay != nil {
		state.tpctlIPv6Overlay.enabled = state.crosshairEnabled
		state.tpctlIPv6Overlay.Refresh()
	}
	if state.jitterOverlay != nil {
		state.jitterOverlay.enabled = state.crosshairEnabled
		state.jitterOverlay.Refresh()
	}
	if state.covOverlay != nil {
		state.covOverlay.enabled = state.crosshairEnabled
		state.covOverlay.Refresh()
	}
	if state.plCountOverlay != nil {
		state.plCountOverlay.enabled = state.crosshairEnabled
		state.plCountOverlay.Refresh()
	}
	if state.plLongestOverlay != nil {
		state.plLongestOverlay.enabled = state.crosshairEnabled
		state.plLongestOverlay.Refresh()
	}
	if state.plStableOverlay != nil {
		state.plStableOverlay.enabled = state.crosshairEnabled
		state.plStableOverlay.Refresh()
	}
	if state.cacheOverlay != nil {
		state.cacheOverlay.enabled = state.crosshairEnabled
		state.cacheOverlay.Refresh()
	}
	if state.proxyOverlay != nil {
		state.proxyOverlay.enabled = state.crosshairEnabled
		state.proxyOverlay.Refresh()
	}
	if state.warmCacheOverlay != nil {
		state.warmCacheOverlay.enabled = state.crosshairEnabled
		state.warmCacheOverlay.Refresh()
	}
	// Always load data once at startup (will fallback to monitor_results.jsonl if available)
	loadAll(state, fileLabel)

	// (removed: compare view initial toggle; percentiles always shown in stack now)

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
	exportPctlOverall := fyne.NewMenuItem("Export Percentiles – Overall…", func() { exportChartPNG(state, state.pctlOverallImg, "percentiles_overall.png") })
	exportPctlIPv4 := fyne.NewMenuItem("Export Percentiles – IPv4…", func() { exportChartPNG(state, state.pctlIPv4Img, "percentiles_ipv4.png") })
	exportPctlIPv6 := fyne.NewMenuItem("Export Percentiles – IPv6…", func() { exportChartPNG(state, state.pctlIPv6Img, "percentiles_ipv6.png") })
	// TTFB percentiles exports
	exportTPctlOverall := fyne.NewMenuItem("Export TTFB Percentiles – Overall…", func() { exportChartPNG(state, state.tpctlOverallImg, "ttfb_percentiles_overall.png") })
	exportTPctlIPv4 := fyne.NewMenuItem("Export TTFB Percentiles – IPv4…", func() { exportChartPNG(state, state.tpctlIPv4Img, "ttfb_percentiles_ipv4.png") })
	exportTPctlIPv6 := fyne.NewMenuItem("Export TTFB Percentiles – IPv6…", func() { exportChartPNG(state, state.tpctlIPv6Img, "ttfb_percentiles_ipv6.png") })
	exportErrors := fyne.NewMenuItem("Export Error Rate Chart…", func() { exportChartPNG(state, state.errImgCanvas, "error_rate_chart.png") })
	exportJitter := fyne.NewMenuItem("Export Jitter Chart…", func() { exportChartPNG(state, state.jitterImgCanvas, "jitter_chart.png") })
	exportCoV := fyne.NewMenuItem("Export CoV Chart…", func() { exportChartPNG(state, state.covImgCanvas, "cov_chart.png") })
	exportCache := fyne.NewMenuItem("Export Cache Hit Rate Chart…", func() { exportChartPNG(state, state.cacheImgCanvas, "cache_hit_rate_chart.png") })
	exportProxy := fyne.NewMenuItem("Export Proxy Suspected Rate Chart…", func() { exportChartPNG(state, state.proxyImgCanvas, "proxy_suspected_rate_chart.png") })
	exportWarmCache := fyne.NewMenuItem("Export Warm Cache Suspected Rate Chart…", func() { exportChartPNG(state, state.warmCacheImgCanvas, "warm_cache_suspected_rate_chart.png") })
	exportPlCount := fyne.NewMenuItem("Export Plateau Count Chart…", func() { exportChartPNG(state, state.plCountImgCanvas, "plateau_count_chart.png") })
	exportPlLongest := fyne.NewMenuItem("Export Longest Plateau Chart…", func() { exportChartPNG(state, state.plLongestImgCanvas, "plateau_longest_chart.png") })
	exportPlStable := fyne.NewMenuItem("Export Plateau Stable Rate Chart…", func() { exportChartPNG(state, state.plStableImgCanvas, "plateau_stable_rate_chart.png") })
	exportAll := fyne.NewMenuItem("Export All Charts (One Image)…", func() { exportAllChartsCombined(state) })
	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Open…", func() { openFileDialog(state, fileLabel) }),
		fyne.NewMenuItem("Reload", func() { loadAll(state, fileLabel) }),
		fyne.NewMenuItemSeparator(),
		exportSpeed,
		exportTTFB,
		exportPctlOverall,
		exportPctlIPv4,
		exportPctlIPv6,
	exportTPctlOverall,
	exportTPctlIPv4,
	exportTPctlIPv6,
		exportErrors,
		exportJitter,
		exportCoV,
		exportCache,
		exportProxy,
		exportWarmCache,
		exportPlCount,
		exportPlLongest,
		exportPlStable,
		fyne.NewMenuItemSeparator(),
		exportAll,
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
	// Build situation index directly from summaries to avoid re-scanning and mismatches
	state.runTagSituation = map[string]string{}
	for _, s := range state.summaries {
		state.runTagSituation[s.RunTag] = s.Situation
	}
	state.situations = uniqueSituationsFromMap(state.runTagSituation)
	// Log counts by situation to help verify filtering covers all batches
	if len(state.summaries) > 0 {
		counts := map[string]int{}
		for _, s := range state.summaries {
			k := s.Situation
			if k == "" {
				k = "(none)"
			}
			counts[k]++
		}
		var parts []string
		for _, k := range state.situations {
			parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
		}
		// include empty situation bucket if present
		if counts["(none)"] > 0 {
			parts = append(parts, fmt.Sprintf("(none)=%d", counts["(none)"]))
		}
		fmt.Printf("[viewer] loaded %d batches. Situation counts: %s\n", len(state.summaries), strings.Join(parts, ", "))
	}
	// Do not auto-select a specific situation; keep default as All
	// update situation selector
	if state.situationSelect != nil {
		opts := make([]string, 0, len(state.situations)+1)
		opts = append(opts, "All")
		opts = append(opts, state.situations...)
		state.situationSelect.Options = opts
		// Default to All unless a specific situation was previously chosen
		if state.situation == "" {
			state.situationSelect.Selected = "All"
		} else {
			state.situationSelect.Selected = state.situation
		}
		state.situationSelect.Refresh()
	}
	if state.table != nil {
		state.table.Refresh()
	}
	updateColumnVisibility(state)
	redrawCharts(state)
}

// (old uniqueSituations removed; we now use meta-driven mapping)

// uniqueSituationsFromMap returns sorted unique non-empty situations from mapping
func uniqueSituationsFromMap(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, v := range m {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func filteredSummaries(state *uiState) []analysis.BatchSummary {
	if state == nil {
		return nil
	}
	if state.situation == "" {
		return state.summaries
	}
	out := make([]analysis.BatchSummary, 0, len(state.summaries))
	for _, s := range state.summaries {
		// Prefer the situation embedded in the summary, fall back to the mapping if needed
		if strings.EqualFold(s.Situation, state.situation) {
			out = append(out, s)
			continue
		}
		if sit, ok := state.runTagSituation[s.RunTag]; ok && strings.EqualFold(sit, state.situation) {
			out = append(out, s)
		}
	}
	return out
}

func redrawCharts(state *uiState) {
	// Speed chart
	spImg := renderSpeedChart(state)
	if spImg != nil {
		if state.speedImgCanvas != nil {
			state.speedImgCanvas.Image = spImg
		}
		// ensure the image reserves enough width/height to show the rendered chart
		cw, chh := chartSize(state)
		if state.speedImgCanvas != nil {
			state.speedImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
			state.speedImgCanvas.Refresh()
		}
		// also refresh overlay so crosshair rebinds to new image rects
		if state.speedOverlay != nil {
			state.speedOverlay.Refresh()
		}
	}
	ttImg := renderTTFBChart(state)
	if ttImg != nil {
		if state.ttfbImgCanvas != nil {
			state.ttfbImgCanvas.Image = ttImg
		}
		cw, chh := chartSize(state)
		if state.ttfbImgCanvas != nil {
			state.ttfbImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
			state.ttfbImgCanvas.Refresh()
		}
		if state.ttfbOverlay != nil {
			state.ttfbOverlay.Refresh()
		}
	}
	// Percentiles chart(s) stacked: Overall, IPv4, IPv6; visibility via checkboxes
	if state.pctlOverallImg != nil {
		if state.showOverall {
			img := renderPercentilesChartWithFamily(state, "overall")
			if img != nil {
				state.pctlOverallImg.Image = img
				cw, chh := chartSize(state)
				state.pctlOverallImg.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.pctlOverallImg.Show()
				state.pctlOverallImg.Refresh()
				if state.pctlOverallOverlay != nil {
					state.pctlOverallOverlay.Refresh()
				}
			}
		} else {
			state.pctlOverallImg.Hide()
		}
	}
	if state.pctlIPv4Img != nil {
		if state.showIPv4 {
			img := renderPercentilesChartWithFamily(state, "ipv4")
			if img != nil {
				state.pctlIPv4Img.Image = img
				cw, chh := chartSize(state)
				state.pctlIPv4Img.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.pctlIPv4Img.Show()
				state.pctlIPv4Img.Refresh()
				if state.pctlIPv4Overlay != nil {
					state.pctlIPv4Overlay.Refresh()
				}
			}
		} else {
			state.pctlIPv4Img.Hide()
		}
	}
	if state.pctlIPv6Img != nil {
		if state.showIPv6 {
			img := renderPercentilesChartWithFamily(state, "ipv6")
			if img != nil {
				state.pctlIPv6Img.Image = img
				cw, chh := chartSize(state)
				state.pctlIPv6Img.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.pctlIPv6Img.Show()
				state.pctlIPv6Img.Refresh()
				if state.pctlIPv6Overlay != nil {
					state.pctlIPv6Overlay.Refresh()
				}
			}
		} else {
			state.pctlIPv6Img.Hide()
		}
	}
	if state.pctlGrid != nil {
		state.pctlGrid.Refresh()
	}
	// TTFB Percentiles chart(s): Overall, IPv4, IPv6
	if state.tpctlOverallImg != nil {
		if state.showOverall {
			img := renderTTFBPercentilesChartWithFamily(state, "overall")
			if img != nil {
				state.tpctlOverallImg.Image = img
				cw, chh := chartSize(state)
				state.tpctlOverallImg.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.tpctlOverallImg.Show()
				state.tpctlOverallImg.Refresh()
				if state.tpctlOverallOverlay != nil {
					state.tpctlOverallOverlay.Refresh()
				}
			}
		} else {
			state.tpctlOverallImg.Hide()
		}
	}
	if state.tpctlIPv4Img != nil {
		if state.showIPv4 {
			img := renderTTFBPercentilesChartWithFamily(state, "ipv4")
			if img != nil {
				state.tpctlIPv4Img.Image = img
				cw, chh := chartSize(state)
				state.tpctlIPv4Img.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.tpctlIPv4Img.Show()
				state.tpctlIPv4Img.Refresh()
				if state.tpctlIPv4Overlay != nil {
					state.tpctlIPv4Overlay.Refresh()
				}
			}
		} else {
			state.tpctlIPv4Img.Hide()
		}
	}
	if state.tpctlIPv6Img != nil {
		if state.showIPv6 {
			img := renderTTFBPercentilesChartWithFamily(state, "ipv6")
			if img != nil {
				state.tpctlIPv6Img.Image = img
				cw, chh := chartSize(state)
				state.tpctlIPv6Img.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.tpctlIPv6Img.Show()
				state.tpctlIPv6Img.Refresh()
				if state.tpctlIPv6Overlay != nil {
					state.tpctlIPv6Overlay.Refresh()
				}
			}
		} else {
			state.tpctlIPv6Img.Hide()
		}
	}
	// Error Rate chart
	erImg := renderErrorRateChart(state)
	if erImg != nil {
		if state.errImgCanvas != nil {
			state.errImgCanvas.Image = erImg
		}
		cw, chh := chartSize(state)
		if state.errImgCanvas != nil {
			state.errImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
			state.errImgCanvas.Refresh()
		}
		if state.errOverlay != nil {
			state.errOverlay.Refresh()
		}
	}
	// Jitter chart
	jitImg := renderJitterChart(state)
	if jitImg != nil {
		if state.jitterImgCanvas != nil {
			state.jitterImgCanvas.Image = jitImg
		}
		cw, chh := chartSize(state)
		if state.jitterImgCanvas != nil {
			state.jitterImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
			state.jitterImgCanvas.Refresh()
		}
		if state.jitterOverlay != nil {
			state.jitterOverlay.Refresh()
		}
	}
	// Coefficient of Variation chart
	covImg := renderCoVChart(state)
	if covImg != nil {
		if state.covImgCanvas != nil {
			state.covImgCanvas.Image = covImg
		}
		cw, chh := chartSize(state)
		if state.covImgCanvas != nil {
			state.covImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
			state.covImgCanvas.Refresh()
		}
		if state.covOverlay != nil {
			state.covOverlay.Refresh()
		}
		// Cache Hit Rate chart
		cacheImg := renderCacheHitRateChart(state)
		if cacheImg != nil {
			if state.cacheImgCanvas != nil {
				state.cacheImgCanvas.Image = cacheImg
			}
			cw, chh := chartSize(state)
			if state.cacheImgCanvas != nil {
				state.cacheImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.cacheImgCanvas.Refresh()
			}
			if state.cacheOverlay != nil {
				state.cacheOverlay.Refresh()
			}
		}
		// Proxy Suspected Rate chart
		proxyImg := renderProxySuspectedRateChart(state)
		if proxyImg != nil {
			if state.proxyImgCanvas != nil {
				state.proxyImgCanvas.Image = proxyImg
			}
			cw, chh := chartSize(state)
			if state.proxyImgCanvas != nil {
				state.proxyImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.proxyImgCanvas.Refresh()
			}
			if state.proxyOverlay != nil {
				state.proxyOverlay.Refresh()
			}
		}
		// Warm Cache Suspected Rate chart
		warmImg := renderWarmCacheSuspectedRateChart(state)
		if warmImg != nil {
			if state.warmCacheImgCanvas != nil {
				state.warmCacheImgCanvas.Image = warmImg
			}
			cw, chh := chartSize(state)
			if state.warmCacheImgCanvas != nil {
				state.warmCacheImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.warmCacheImgCanvas.Refresh()
			}
			if state.warmCacheOverlay != nil {
				state.warmCacheOverlay.Refresh()
			}
		}
		// Plateau Count chart
		plcImg := renderPlateauCountChart(state)
		if plcImg != nil {
			if state.plCountImgCanvas != nil {
				state.plCountImgCanvas.Image = plcImg
			}
			cw, chh := chartSize(state)
			if state.plCountImgCanvas != nil {
				state.plCountImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.plCountImgCanvas.Refresh()
			}
			if state.plCountOverlay != nil {
				state.plCountOverlay.Refresh()
			}
		}
		// Longest Plateau chart
		pllImg := renderPlateauLongestChart(state)
		if pllImg != nil {
			if state.plLongestImgCanvas != nil {
				state.plLongestImgCanvas.Image = pllImg
			}
			cw, chh := chartSize(state)
			if state.plLongestImgCanvas != nil {
				state.plLongestImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.plLongestImgCanvas.Refresh()
			}
			if state.plLongestOverlay != nil {
				state.plLongestOverlay.Refresh()
			}
		}
		// Plateau Stable Rate chart
		plsImg := renderPlateauStableChart(state)
		if plsImg != nil {
			if state.plStableImgCanvas != nil {
				state.plStableImgCanvas.Image = plsImg
			}
			cw, chh := chartSize(state)
			if state.plStableImgCanvas != nil {
				state.plStableImgCanvas.SetMinSize(fyne.NewSize(float32(cw), float32(chh)))
				state.plStableImgCanvas.Refresh()
			}
			if state.plStableOverlay != nil {
				state.plStableOverlay.Refresh()
			}
		}
	}
}
// renderTTFBPercentilesChartWithFamily draws TTFB percentiles (ms) for the given family (overall/ipv4/ipv6).
func renderTTFBPercentilesChartWithFamily(state *uiState, fam string) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := compareChartSize(state)
		return blank(w, h)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY := math.MaxFloat64
	maxY := -math.MaxFloat64

	add := func(name string, sel func(analysis.BatchSummary) float64, color drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY { minY = v }
			if v > maxY { maxY = v }
			valid++
		}
		st := pointStyle(color)
		if valid == 1 { st.DotWidth = 6 }
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}

	fam = strings.ToLower(strings.TrimSpace(fam))
	switch fam {
	case "ipv4":
		add("P50", func(b analysis.BatchSummary) float64 { if b.IPv4==nil {return 0}; return b.IPv4.AvgP50TTFBMs }, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 { if b.IPv4==nil {return 0}; return b.IPv4.AvgP90TTFBMs }, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 { if b.IPv4==nil {return 0}; return b.IPv4.AvgP95TTFBMs }, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 { if b.IPv4==nil {return 0}; return b.IPv4.AvgP99TTFBMs }, chart.ColorRed)
	case "ipv6":
		add("P50", func(b analysis.BatchSummary) float64 { if b.IPv6==nil {return 0}; return b.IPv6.AvgP50TTFBMs }, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 { if b.IPv6==nil {return 0}; return b.IPv6.AvgP90TTFBMs }, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 { if b.IPv6==nil {return 0}; return b.IPv6.AvgP95TTFBMs }, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 { if b.IPv6==nil {return 0}; return b.IPv6.AvgP99TTFBMs }, chart.ColorRed)
	default:
		add("P50", func(b analysis.BatchSummary) float64 { return b.AvgP50TTFBMs }, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 { return b.AvgP90TTFBMs }, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 { return b.AvgP95TTFBMs }, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 { return b.AvgP99TTFBMs }, chart.ColorRed)
	}

	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY { maxY = minY + 1 }
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 4)
	} else if !state.useRelative && haveY {
		if maxY <= 0 { maxY = 1 }
		_, nMax := niceAxisBounds(0, maxY)
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: nMax}
	}
	padBottom := 28
	switch state.xAxisMode { case "run_tag": padBottom = 90; case "time": padBottom = 48 }
	if state.showHints { padBottom += 18 }

	var titlePrefix string
	switch fam {
	case "ipv4": titlePrefix = "IPv4 "
	case "ipv6": titlePrefix = "IPv6 "
	default: titlePrefix = "Overall "
	}
	ch := chart.Chart{
		Title:      fmt.Sprintf("%sTTFB Percentiles (ms)%s", titlePrefix, situationSuffix(state)),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	cw, chh := chartSize(state)
	ch.Width = cw
	ch.Height = chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil { return blank(cw, chh) }
	img, err := png.Decode(&buf); if err != nil { return blank(cw, chh) }
	if state.showHints { img = drawHint(img, "Hint: TTFB percentiles capture latency distribution. Wider gaps indicate latency spikes.") }
	return img
}

// renderCacheHitRateChart draws CacheHitRatePct per batch (overall/IPv4/IPv6).
func renderCacheHitRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(col)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return b.CacheHitRatePct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.CacheHitRatePct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.CacheHitRatePct
		}, chart.ColorGreen)
	}
	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		if maxY < 1 {
			maxY = 1
		}
		if maxY > 100 {
			maxY = 100
		}
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: 100}
		yTicks = []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{Title: fmt.Sprintf("Cache Hit Rate (%%)%s", situationSuffix(state)), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] cache-hit render error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] cache-hit decode error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: Cache hit rate. Higher can mean content already cached near you.")
	}
	return img
}

// renderProxySuspectedRateChart draws ProxySuspectedRatePct per batch (overall/IPv4/IPv6).
func renderProxySuspectedRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(col)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return b.ProxySuspectedRatePct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.ProxySuspectedRatePct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.ProxySuspectedRatePct
		}, chart.ColorGreen)
	}
	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		if maxY < 1 {
			maxY = 1
		}
		if maxY > 100 {
			maxY = 100
		}
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: 100}
		yTicks = []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{Title: fmt.Sprintf("Proxy Suspected Rate (%%)%s", situationSuffix(state)), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] proxy-suspected render error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] proxy-suspected decode error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: How often a proxy is suspected. Spikes can indicate transit via middleboxes.")
	}
	return img
}

// renderWarmCacheSuspectedRateChart draws WarmCacheSuspectedRatePct per batch (overall/IPv4/IPv6).
func renderWarmCacheSuspectedRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(col)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return b.WarmCacheSuspectedRatePct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.WarmCacheSuspectedRatePct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.WarmCacheSuspectedRatePct
		}, chart.ColorGreen)
	}
	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		if maxY < 1 {
			maxY = 1
		}
		if maxY > 100 {
			maxY = 100
		}
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: 100}
		yTicks = []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{Title: fmt.Sprintf("Warm Cache Suspected Rate (%%)%s", situationSuffix(state)), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] warm-cache render error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] warm-cache decode error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: Warm-cache suspected rate. Higher suggests repeated content or prior fetch effects.")
	}
	return img
}

// chartSize computes a chart size based on the current window width so charts use more X-axis space.
func chartSize(state *uiState) (int, int) {
	if state == nil || state.window == nil || state.window.Canvas() == nil {
		return 1100, 340
	}
	sz := state.window.Canvas().Size()
	// Use ~95% of the available width, minus a small margin for scrollbars/padding
	w := int(sz.Width*0.95) - 12
	if w < 800 {
		w = 800
	}
	// Maintain a ~3:1 aspect ratio, with sane bounds
	h := int(float32(w) * 0.33)
	if h < 280 {
		h = 280
	}
	if h > 520 {
		h = 520
	}
	return w, h
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
	maxY := -math.MaxFloat64

	if state.showOverall {
		ys := make([]float64, len(rows))
		countValid := 0
		for i, r := range rows {
			v := r.AvgSpeed * factor
			ys[i] = v
			if !math.IsNaN(v) {
				if v < minY {
					minY = v
				}
				if v > maxY {
					maxY = v
				}
				countValid++
			}
		}
		st := pointStyle(chart.ColorAlternateGray)
		if countValid == 1 { // emphasize single-point sets
			st.DotWidth = 6
		}
		if timeMode {
			// Pad to at least two X values for go-chart
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: "Overall", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: "Overall", XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: "Overall", XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: "Overall", XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showIPv4 {
		ys := make([]float64, len(rows))
		countValid := 0
		for i, r := range rows {
			var v float64
			if r.IPv4 != nil {
				v = r.IPv4.AvgSpeed * factor
			} else {
				v = math.NaN()
			}
			ys[i] = v
			if !math.IsNaN(v) {
				if v < minY {
					minY = v
				}
				if v > maxY {
					maxY = v
				}
				countValid++
			}
		}
		st := pointStyle(chart.ColorBlue)
		if countValid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: "IPv4", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: "IPv4", XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: "IPv4", XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: "IPv4", XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showIPv6 {
		ys := make([]float64, len(rows))
		countValid := 0
		for i, r := range rows {
			var v float64
			if r.IPv6 != nil {
				v = r.IPv6.AvgSpeed * factor
			} else {
				v = math.NaN()
			}
			ys[i] = v
			if !math.IsNaN(v) {
				if v < minY {
					minY = v
				}
				if v > maxY {
					maxY = v
				}
				countValid++
			}
		}
		st := pointStyle(chart.ColorGreen)
		if countValid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: "IPv6", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: "IPv6", XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: "IPv6", XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: "IPv6", XValues: xs, YValues: ys, Style: st})
			}
		}
	}

	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		// Absolute mode: baseline at 0 with a nice rounded max
		// Ensure a minimal positive height when there's a single value
		if maxY <= 0 {
			maxY = 1
		}
		_, nMax := niceAxisBounds(0, maxY)
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: nMax}
	}
	// More bottom padding when X-axis labels are long
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	// if hints are enabled, increase bottom padding for hint text
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{
		Title:      fmt.Sprintf("Avg Speed (%s)%s", unitName, situationSuffix(state)),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: unitName, Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	if len(rows) == 1 {
		// Debug series lengths to understand x-range errors
		for i, s := range series {
			switch ss := s.(type) {
			case chart.TimeSeries:
				fmt.Printf("[viewer] speed series[%d] TimeSeries X=%d Y=%d\n", i, len(ss.XValues), len(ss.YValues))
			case chart.ContinuousSeries:
				fmt.Printf("[viewer] speed series[%d] Continuous X=%d Y=%d\n", i, len(ss.XValues), len(ss.YValues))
			default:
				fmt.Printf("[viewer] speed series[%d] type=%T\n", i, s)
			}
		}
	}
	// Size chart to use window width so X-axis has more space
	cw, chh := chartSize(state)
	ch.Width = cw
	ch.Height = chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}

	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		// Fallback to a blank image so the UI visibly updates even on render errors (e.g., single-point edge cases)
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] speed chart render error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] speed chart decode error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: Speed trends. Drops may indicate congestion, Wi‑Fi issues, or ISP problems.")
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
	maxY := -math.MaxFloat64

	if state.showOverall {
		ys := make([]float64, len(rows))
		countValid := 0
		for i, r := range rows {
			v := r.AvgTTFB
			ys[i] = v
			if !math.IsNaN(v) {
				if v < minY {
					minY = v
				}
				if v > maxY {
					maxY = v
				}
				countValid++
			}
		}
		st := pointStyle(chart.ColorAlternateGray)
		if countValid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: "Overall", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: "Overall", XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: "Overall", XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: "Overall", XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showIPv4 {
		ys := make([]float64, len(rows))
		countValid := 0
		for i, r := range rows {
			var v float64
			if r.IPv4 != nil {
				v = r.IPv4.AvgTTFB
			} else {
				v = math.NaN()
			}
			ys[i] = v
			if !math.IsNaN(v) {
				if v < minY {
					minY = v
				}
				if v > maxY {
					maxY = v
				}
				countValid++
			}
		}
		st := pointStyle(chart.ColorBlue)
		if countValid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: "IPv4", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: "IPv4", XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: "IPv4", XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: "IPv4", XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showIPv6 {
		ys := make([]float64, len(rows))
		countValid := 0
		for i, r := range rows {
			var v float64
			if r.IPv6 != nil {
				v = r.IPv6.AvgTTFB
			} else {
				v = math.NaN()
			}
			ys[i] = v
			if !math.IsNaN(v) {
				if v < minY {
					minY = v
				}
				if v > maxY {
					maxY = v
				}
				countValid++
			}
		}
		st := pointStyle(chart.ColorGreen)
		if countValid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: "IPv6", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: "IPv6", XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: "IPv6", XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: "IPv6", XValues: xs, YValues: ys, Style: st})
			}
		}
	}

	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		// Absolute mode: baseline at 0 with a nice rounded max
		if maxY <= 0 {
			maxY = 1
		}
		_, nMax := niceAxisBounds(0, maxY)
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: nMax}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{
		Title:      fmt.Sprintf("Avg TTFB (ms)%s", situationSuffix(state)),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	if len(rows) == 1 {
		for i, s := range series {
			switch ss := s.(type) {
			case chart.TimeSeries:
				fmt.Printf("[viewer] ttfb series[%d] TimeSeries X=%d Y=%d\n", i, len(ss.XValues), len(ss.YValues))
			case chart.ContinuousSeries:
				fmt.Printf("[viewer] ttfb series[%d] Continuous X=%d Y=%d\n", i, len(ss.XValues), len(ss.YValues))
			default:
				fmt.Printf("[viewer] ttfb series[%d] type=%T\n", i, s)
			}
		}
	}
	cw, chh := chartSize(state)
	ch.Width = cw
	ch.Height = chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}

	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] ttfb chart render error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] ttfb chart decode error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: TTFB reflects latency. Spikes often point to DNS/TLS/connect issues or remote slowness.")
	}
	return img
}

// renderErrorRateChart draws error percentage per batch for overall, IPv4, IPv6.
func renderErrorRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY := math.MaxFloat64
	maxY := -math.MaxFloat64

	// helper to add a line for selector
	add := func(name string, sel func(analysis.BatchSummary) (num, den int), color drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			n, d := sel(r)
			if d <= 0 {
				ys[i] = math.NaN()
				continue
			}
			v := float64(n) / float64(d) * 100.0
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(color)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}

	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) (int, int) { return b.ErrorLines, b.Lines }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) (int, int) {
			if b.IPv4 == nil {
				return 0, 0
			}
			return b.IPv4.ErrorLines, b.IPv4.Lines
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) (int, int) {
			if b.IPv6 == nil {
				return 0, 0
			}
			return b.IPv6.ErrorLines, b.IPv6.Lines
		}, chart.ColorGreen)
	}

	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		// Absolute: clamp 0..100
		if maxY < 1 {
			maxY = 1
		}
		if maxY > 100 {
			maxY = 100
		}
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: 100}
		yTicks = []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{
		Title:      fmt.Sprintf("Error Rate (%%)%s", situationSuffix(state)),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	cw, chh := chartSize(state)
	ch.Width = cw
	ch.Height = chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}

	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] error chart render error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] error chart decode error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: Error rate per batch (overall and per‑family). Spikes often correlate with outages or auth/firewall issues.")
	}
	return img
}

// renderJitterChart draws AvgJitterPct per batch for overall, IPv4, IPv6.
func renderJitterChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, color drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(color)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgJitterPct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgJitterPct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgJitterPct
		}, chart.ColorGreen)
	}
	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		if maxY < 1 {
			maxY = 1
		}
		if maxY > 100 {
			maxY = 100
		}
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: 100}
		yTicks = []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{Title: fmt.Sprintf("Jitter (%%)%s", situationSuffix(state)), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] jitter chart render error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] jitter chart decode error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: Jitter measures volatility per batch. Lower is more stable.")
	}
	return img
}

// renderCoVChart draws AvgCoefVariationPct per batch (overall/IPv4/IPv6).
func renderCoVChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, color drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(color)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgCoefVariationPct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgCoefVariationPct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgCoefVariationPct
		}, chart.ColorGreen)
	}
	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		if maxY < 1 {
			maxY = 1
		}
		if maxY > 200 {
			maxY = 200
		}
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: maxY}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{Title: fmt.Sprintf("Coefficient of Variation (%%)%s", situationSuffix(state)), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] cov chart render error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] cov chart decode error: %v; showing blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: CoV shows relative variability (stddev/mean). Lower is steadier.")
	}
	return img
}

// renderPlateauCountChart plots AvgPlateauCount per batch.
func renderPlateauCountChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(col)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgPlateauCount }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgPlateauCount
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgPlateauCount
		}, chart.ColorGreen)
	}
	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		// baseline at 0 with a nice rounded max
		if maxY <= 1 {
			maxY = 2
		}
		_, nMax := niceAxisBounds(0, maxY)
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: nMax}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{Title: fmt.Sprintf("Plateau Count%s", situationSuffix(state)), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "count", Range: yAxisRange, Ticks: yTicks}, Series: series}
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] plateau-count render error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] plateau-count decode error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: Number of distinct speed plateaus per batch. Fewer can indicate steadier transfer.")
	}
	return img
}

// renderPlateauLongestChart plots AvgLongestPlateau (ms) per batch.
func renderPlateauLongestChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(col)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgLongestPlateau }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgLongestPlateau
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgLongestPlateau
		}, chart.ColorGreen)
	}
	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		if maxY <= 10 {
			maxY = 10
		}
		_, nMax := niceAxisBounds(0, maxY)
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: nMax}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{Title: fmt.Sprintf("Longest Plateau (ms)%s", situationSuffix(state)), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks}, Series: series}
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] plateau-longest render error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] plateau-longest decode error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: Longest plateau duration in ms. Longer plateaus may indicate throttling or buffering.")
	}
	return img
}

// renderPlateauStableChart plots PlateauStableRatePct (percentage) per batch for overall/IPv4/IPv6.
func renderPlateauStableChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		return blank(800, 320)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(col)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return b.PlateauStableRatePct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.PlateauStableRatePct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.PlateauStableRatePct
		}, chart.ColorGreen)
	}
	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
		// clamp 0..100
		if maxY < 1 {
			maxY = 1
		}
		if maxY > 100 {
			maxY = 100
		}
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: 100}
		yTicks = []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}
	ch := chart.Chart{Title: fmt.Sprintf("Plateau Stable Rate (%%)%s", situationSuffix(state)), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] plateau-stable render error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		cw, chh := chartSize(state)
		fmt.Printf("[viewer] plateau-stable decode error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		return drawHint(img, "Hint: Share of lines with stable speed plateau within batch. Higher is steadier.")
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
			t := parseRunTagTime(r.RunTag)
			if idx := strings.LastIndex(r.RunTag, "_i"); idx >= 0 {
				if n, err := strconv.Atoi(r.RunTag[idx+2:]); err == nil {
					t = t.Add(time.Duration(n) * time.Second)
				}
			}
			ts[i] = t
		}
		// Ensure strictly non-decreasing sequence
		for i := 1; i < len(ts); i++ {
			if !ts[i].After(ts[i-1]) {
				ts[i] = ts[i-1].Add(1 * time.Second)
			}
		}
		// Build nice rounded ticks across the time span
		if len(ts) == 0 {
			return true, ts, nil, chart.XAxis{Name: "Time"}
		}
		minT := ts[0]
		maxT := ts[0]
		for _, t := range ts[1:] {
			if t.Before(minT) {
				minT = t
			}
			if t.After(maxT) {
				maxT = t
			}
		}
		step, labFmt := pickTimeStep(maxT.Sub(minT))
		ticks := makeNiceTimeTicks(minT, maxT, step, labFmt)
		if len(ts) == 1 && len(ticks) < 2 {
			// add a second tick one step later to keep axis happy
			ticks = append(ticks, chart.Tick{Value: float64(chart.TimeToFloat64(minT.Add(step))), Label: minT.Add(step).Local().Format(labFmt)})
		}
		// Ensure non-zero X range even when there's only one timestamp
		minF := float64(chart.TimeToFloat64(minT))
		maxF := float64(chart.TimeToFloat64(maxT))
		if maxF <= minF {
			maxF = minF + float64(step/time.Second)
			if maxF <= minF { // fallback to +1s
				maxF = minF + 1
			}
		}
		xa := chart.XAxis{Name: "Time", Ticks: ticks, Range: &chart.ContinuousRange{Min: minF, Max: maxF}}
		if len(ts) == 1 {
			fmt.Printf("[viewer] time axis padded: min=%v max=%v ticks=%d\n", minT, maxT, len(ticks))
		}
		return true, ts, nil, xa
	case "run_tag":
		n := len(rows)
		xs := make([]float64, n)
		ticks := make([]chart.Tick, 0, n+1)
		for i, r := range rows {
			x := float64(i + 1)
			xs[i] = x
			ticks = append(ticks, chart.Tick{Value: x, Label: r.RunTag})
		}
		// Provide an explicit range so n=1 still renders with non-zero width
		minR := 0.5
		maxR := float64(n) + 0.5
		if n == 1 {
			maxR = 2.0 // make sure delta > 0
			ticks = append(ticks, chart.Tick{Value: 2, Label: ""})
		}
		xa := chart.XAxis{Name: "RunTag", Ticks: ticks, Range: &chart.ContinuousRange{Min: minR, Max: maxR}}
		return false, nil, xs, xa
	default:
		n := len(rows)
		xs := make([]float64, n)
		ticks := make([]chart.Tick, 0, n+1)
		for i := 0; i < n; i++ {
			x := float64(i + 1)
			xs[i] = x
			ticks = append(ticks, chart.Tick{Value: x, Label: fmt.Sprintf("%d", i+1)})
		}
		// Provide explicit integer ticks and a padded range so n=1 renders properly
		minR := 0.5
		maxR := float64(n) + 0.5
		if n == 1 {
			maxR = 2.0
			ticks = append(ticks, chart.Tick{Value: 2, Label: ""})
		}
		xa := chart.XAxis{
			Name:  "Batch",
			Ticks: ticks,
			Range: &chart.ContinuousRange{Min: minR, Max: maxR},
		}
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

// niceAxisBounds expands [min,max] by a small margin and rounds to "nice" numbers for readability.
func niceAxisBounds(min, max float64) (float64, float64) {
	if math.IsNaN(min) || math.IsNaN(max) {
		return min, max
	}
	if max <= min {
		max = min + 1
	}
	span := max - min
	// 5% margin on both sides
	pad := span * 0.05
	if pad <= 0 {
		pad = 1
	}
	a := min - pad
	b := max + pad
	// round to nearest "nice" increments based on span order of magnitude
	mag := math.Pow(10, math.Floor(math.Log10(span)))
	if !math.IsInf(mag, 0) && mag > 0 {
		a = math.Floor(a/mag) * mag
		b = math.Ceil(b/mag) * mag
	}
	return a, b
}

// niceTicks generates up to n desired tick marks between [min, max] using nice increments.
func niceTicks(min, max float64, n int) []chart.Tick {
	if n < 2 || math.IsNaN(min) || math.IsNaN(max) {
		return nil
	}
	if max <= min {
		max = min + 1
	}
	span := max - min
	// Preferred tick steps: 1, 2, 2.5, 5, 10 ... scaled by power of 10
	mag := math.Pow(10, math.Floor(math.Log10(span/float64(n-1))))
	candidates := []float64{1, 2, 2.5, 5, 10}
	bestStep := mag
	bestScore := math.MaxFloat64
	for _, c := range candidates {
		step := c * mag
		count := math.Ceil((max - min) / step)
		if count < 2 {
			count = 2
		}
		score := math.Abs(count - float64(n))
		if score < bestScore {
			bestScore = score
			bestStep = step
		}
	}
	start := math.Floor(min/bestStep) * bestStep
	end := math.Ceil(max/bestStep) * bestStep
	// limit to a reasonable number of ticks (<= n+2)
	ticks := []chart.Tick{}
	for v := start; v <= end+bestStep/2; v += bestStep {
		ticks = append(ticks, chart.Tick{Value: v, Label: formatTick(v)})
		if len(ticks) > n+2 {
			break
		}
	}
	return ticks
}

func formatTick(v float64) string {
	if v == 0 {
		return "0"
	}
	av := math.Abs(v)
	switch {
	case av >= 1_000_000:
		return fmt.Sprintf("%.0f", v)
	case av >= 100_000:
		return fmt.Sprintf("%.0f", v)
	case av >= 10_000:
		return fmt.Sprintf("%.0f", v)
	case av >= 1000:
		return fmt.Sprintf("%.0f", v)
	case av >= 100:
		return fmt.Sprintf("%.0f", v)
	case av >= 10:
		return fmt.Sprintf("%.1f", v)
	default:
		return fmt.Sprintf("%.2f", v)
	}
}

// drawHint draws a small hint string onto the provided image near the bottom-left.
func drawHint(img image.Image, text string) image.Image {
	if img == nil || strings.TrimSpace(text) == "" {
		return img
	}
	b := img.Bounds()
	rgba := image.NewRGBA(b)
	draw.Draw(rgba, b, img, b.Min, draw.Src)
	// Slight translucent bg for readability
	pad := 6
	// measure text width approximately using 7x13 font
	face := basicfont.Face7x13
	// main text color and shadow
	textCol := image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 255})
	shadowCol := image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 180})
	dr := &font.Drawer{Dst: rgba, Src: textCol, Face: face}
	tw := dr.MeasureString(text).Ceil()
	x := b.Min.X + 8
	y := b.Max.Y - 6
	// Draw background rectangle (semi-opaque dark)
	bg := image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 200})
	rect := image.Rect(x-pad, y-face.Metrics().Ascent.Ceil()-pad, x+tw+pad, y+pad/2)
	draw.Draw(rgba, rect, bg, image.Point{}, draw.Over)
	// Draw shadow then text for better contrast on varying backgrounds
	// Shadow
	drShadow := &font.Drawer{Dst: rgba, Src: shadowCol, Face: face, Dot: fixed.Point26_6{X: fixed.I(x + 1), Y: fixed.I(y + 1)}}
	drShadow.DrawString(text)
	// Main text
	dr.Dot = fixed.Point26_6{X: fixed.I(x), Y: fixed.I(y)}
	dr.DrawString(text)
	return rgba
}

// drawCaption draws a small caption near the top-left of the image.
// (caption overlay removed for cleaner look)

// renderPercentilesChartWithFamily draws a compact percentiles chart for the given family (overall/ipv4/ipv6).
func renderPercentilesChartWithFamily(state *uiState, fam string) image.Image {
	unitName, factor := speedUnitNameAndFactor(state.speedUnit)
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := compareChartSize(state)
		return blank(w, h)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY := math.MaxFloat64
	maxY := -math.MaxFloat64

	add := func(name string, sel func(analysis.BatchSummary) float64, color drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r) * factor
			if v <= 0 {
				ys[i] = math.NaN()
				continue
			}
			ys[i] = v
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
			valid++
		}
		st := pointStyle(color)
		if valid == 1 {
			st.DotWidth = 6
		}
		if timeMode {
			if len(times) == 1 {
				t2 := times[0].Add(1 * time.Second)
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.TimeSeries{Name: name, XValues: []time.Time{times[0], t2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.TimeSeries{Name: name, XValues: times, YValues: ys, Style: st})
			}
		} else {
			if len(xs) == 1 {
				x2 := xs[0] + 1
				ys = append([]float64{ys[0]}, ys[0])
				series = append(series, chart.ContinuousSeries{Name: name, XValues: []float64{xs[0], x2}, YValues: ys, Style: st})
			} else {
				series = append(series, chart.ContinuousSeries{Name: name, XValues: xs, YValues: ys, Style: st})
			}
		}
	}

	fam = strings.ToLower(strings.TrimSpace(fam))
	switch fam {
	case "ipv4":
		add("P50", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgP50Speed
		}, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgP90Speed
		}, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgP95Speed
		}, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgP99Speed
		}, chart.ColorRed)
	case "ipv6":
		add("P50", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP50Speed
		}, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP90Speed
		}, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP95Speed
		}, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP99Speed
		}, chart.ColorRed)
	default:
		add("P50", func(b analysis.BatchSummary) float64 { return b.AvgP50Speed }, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 { return b.AvgP90Speed }, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 { return b.AvgP95Speed }, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 { return b.AvgP99Speed }, chart.ColorRed)
	}

	var yAxisRange *chart.ContinuousRange
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 4)
	} else if !state.useRelative && haveY {
		if maxY <= 0 {
			maxY = 1
		}
		_, nMax := niceAxisBounds(0, maxY)
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: nMax}
	}
	padBottom := 28
	switch state.xAxisMode {
	case "run_tag":
		padBottom = 90
	case "time":
		padBottom = 48
	}
	if state.showHints {
		padBottom += 18
	}

	// Title to match other charts
	var titlePrefix string
	switch strings.ToLower(strings.TrimSpace(fam)) {
	case "ipv4":
		titlePrefix = "IPv4 "
	case "ipv6":
		titlePrefix = "IPv6 "
	default:
		titlePrefix = "Overall "
	}
	ch := chart.Chart{
		Title:      fmt.Sprintf("%sSpeed Percentiles (%s)%s", titlePrefix, unitName, situationSuffix(state)),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: unitName, Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	// Use full-width chart size like the other graphs
	cw, chh := chartSize(state)
	ch.Width = cw
	ch.Height = chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		fmt.Printf("[viewer] percentiles(compare) render error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		fmt.Printf("[viewer] percentiles(compare) decode error: %v; blank fallback\n", err)
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Speed percentiles surface variability. Wider gaps (P99>>P50) mean jittery performance.")
	}
	return img
}

// compareChartSize returns a compact size for side-by-side percentiles charts
func compareChartSize(state *uiState) (int, int) {
	if state == nil || state.window == nil || state.window.Canvas() == nil {
		return 320, 240
	}
	sz := state.window.Canvas().Size()
	totalW := int(sz.Width*0.95) - 12
	if totalW < 600 {
		totalW = 600
	}
	// Three columns with minimal gutters managed by grid; we just target each panel width
	w := totalW / 3
	if w < 260 {
		w = 260
	}
	if w > 520 {
		w = 520
	}
	h := int(float32(w) * 0.8)
	if h < 220 {
		h = 220
	}
	if h > 420 {
		h = 420
	}
	return w, h
}

// pickTimeStep selects a readable step and label format for a given time span.
func pickTimeStep(span time.Duration) (time.Duration, string) {
	// Heuristic thresholds for span to step mapping
	switch {
	case span <= 2*time.Minute:
		return 10 * time.Second, "15:04:05"
	case span <= 10*time.Minute:
		return 1 * time.Minute, "15:04"
	case span <= 30*time.Minute:
		return 5 * time.Minute, "15:04"
	case span <= 2*time.Hour:
		return 10 * time.Minute, "15:04"
	case span <= 6*time.Hour:
		return 30 * time.Minute, "Jan 2 15:04"
	case span <= 24*time.Hour:
		return 1 * time.Hour, "Jan 2 15:04"
	case span <= 3*24*time.Hour:
		return 6 * time.Hour, "Jan 2 15:04"
	case span <= 14*24*time.Hour:
		return 1 * 24 * time.Hour, "Jan 2"
	default:
		return 7 * 24 * time.Hour, "Jan 2"
	}
}

// makeNiceTimeTicks returns rounded ticks between min and max at the given step with labels.
func makeNiceTimeTicks(minT, maxT time.Time, step time.Duration, labelFmt string) []chart.Tick {
	if step <= 0 {
		return nil
	}
	// Round start down to step boundary
	// We align to UTC to avoid DST/local anomalies in labels
	start := minT.UTC()
	// Convert to Unix seconds and round down by step
	s := start.Unix()
	st := int64(step.Seconds())
	if st <= 0 {
		st = 1
	}
	aligned := time.Unix((s/st)*st, 0).UTC()
	// Generate ticks up to max
	ticks := []chart.Tick{}
	for t := aligned; !t.After(maxT.UTC().Add(step)); t = t.Add(step) {
		ticks = append(ticks, chart.Tick{Value: float64(chart.TimeToFloat64(t)), Label: t.Local().Format(labelFmt)})
		if len(ticks) > 20 { // keep it readable
			break
		}
	}
	return ticks
}

// (removed obsolete populateRunTagSituations; we now derive mapping from summaries)

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

// exportAllChartsCombined stitches all currently visible charts into a single tall image and prompts to save.
func exportAllChartsCombined(state *uiState) {
	if state == nil || state.window == nil {
		return
	}
	// Gather images in display order
	imgs := []image.Image{}
	labels := []string{}
	if state.speedImgCanvas != nil && state.speedImgCanvas.Image != nil {
		imgs = append(imgs, state.speedImgCanvas.Image)
		labels = append(labels, "Speed")
	}
	if state.ttfbImgCanvas != nil && state.ttfbImgCanvas.Image != nil {
		imgs = append(imgs, state.ttfbImgCanvas.Image)
		labels = append(labels, "TTFB")
	}
	// Percentiles panels based on visibility
	if state.pctlOverallImg != nil && state.pctlOverallImg.Visible() && state.pctlOverallImg.Image != nil {
		imgs = append(imgs, state.pctlOverallImg.Image)
		labels = append(labels, "Percentiles – Overall")
	}
	if state.pctlIPv4Img != nil && state.pctlIPv4Img.Visible() && state.pctlIPv4Img.Image != nil {
		imgs = append(imgs, state.pctlIPv4Img.Image)
		labels = append(labels, "Percentiles – IPv4")
	}
	if state.pctlIPv6Img != nil && state.pctlIPv6Img.Visible() && state.pctlIPv6Img.Image != nil {
		imgs = append(imgs, state.pctlIPv6Img.Image)
		labels = append(labels, "Percentiles – IPv6")
	}
	// TTFB percentiles panels based on visibility
	if state.tpctlOverallImg != nil && state.tpctlOverallImg.Visible() && state.tpctlOverallImg.Image != nil {
		imgs = append(imgs, state.tpctlOverallImg.Image)
		labels = append(labels, "TTFB Percentiles – Overall")
	}
	if state.tpctlIPv4Img != nil && state.tpctlIPv4Img.Visible() && state.tpctlIPv4Img.Image != nil {
		imgs = append(imgs, state.tpctlIPv4Img.Image)
		labels = append(labels, "TTFB Percentiles – IPv4")
	}
	if state.tpctlIPv6Img != nil && state.tpctlIPv6Img.Visible() && state.tpctlIPv6Img.Image != nil {
		imgs = append(imgs, state.tpctlIPv6Img.Image)
		labels = append(labels, "TTFB Percentiles – IPv6")
	}
	if state.errImgCanvas != nil && state.errImgCanvas.Image != nil {
		imgs = append(imgs, state.errImgCanvas.Image)
		labels = append(labels, "Error Rate")
	}
	if state.jitterImgCanvas != nil && state.jitterImgCanvas.Image != nil {
		imgs = append(imgs, state.jitterImgCanvas.Image)
		labels = append(labels, "Jitter")
	}
	if state.covImgCanvas != nil && state.covImgCanvas.Image != nil {
		imgs = append(imgs, state.covImgCanvas.Image)
		labels = append(labels, "Coefficient of Variation")
	}
	if state.cacheImgCanvas != nil && state.cacheImgCanvas.Image != nil {
		imgs = append(imgs, state.cacheImgCanvas.Image)
		labels = append(labels, "Cache Hit Rate")
	}
	if state.proxyImgCanvas != nil && state.proxyImgCanvas.Image != nil {
		imgs = append(imgs, state.proxyImgCanvas.Image)
		labels = append(labels, "Proxy Suspected Rate")
	}
	if state.warmCacheImgCanvas != nil && state.warmCacheImgCanvas.Image != nil {
		imgs = append(imgs, state.warmCacheImgCanvas.Image)
		labels = append(labels, "Warm Cache Suspected Rate")
	}
	if state.plCountImgCanvas != nil && state.plCountImgCanvas.Image != nil {
		imgs = append(imgs, state.plCountImgCanvas.Image)
		labels = append(labels, "Plateau Count")
	}
	if state.plLongestImgCanvas != nil && state.plLongestImgCanvas.Image != nil {
		imgs = append(imgs, state.plLongestImgCanvas.Image)
		labels = append(labels, "Longest Plateau (ms)")
	}
	if state.plStableImgCanvas != nil && state.plStableImgCanvas.Image != nil {
		imgs = append(imgs, state.plStableImgCanvas.Image)
		labels = append(labels, "Plateau Stable Rate")
	}
	if len(imgs) == 0 {
		dialog.ShowInformation("Export All", "No charts to export.", state.window)
		return
	}
	// Determine max width, total height
	maxW := 0
	totalH := 0
	for _, im := range imgs {
		b := im.Bounds()
		if b.Dx() > maxW {
			maxW = b.Dx()
		}
		totalH += b.Dy()
		// add a separator gap between charts
		totalH += 8
	}
	if totalH > 0 {
		totalH -= 8
	}
	if maxW <= 0 || totalH <= 0 {
		dialog.ShowInformation("Export All", "Charts have no size to export.", state.window)
		return
	}
	// Compose vertically with small gaps
	out := image.NewRGBA(image.Rect(0, 0, maxW, totalH))
	// Fill background dark to match app
	for y := 0; y < totalH; y++ {
		for x := 0; x < maxW; x++ {
			out.SetRGBA(x, y, color.RGBA{R: 18, G: 18, B: 18, A: 255})
		}
	}
	y := 0
	for i, im := range imgs {
		b := im.Bounds()
		// center each chart horizontally
		x := (maxW - b.Dx()) / 2
		draw.Draw(out, image.Rect(x, y, x+b.Dx(), y+b.Dy()), im, b.Min, draw.Over)
		y += b.Dy()
		if i != len(imgs)-1 {
			y += 8
		}
		_ = labels // reserved for future per-section labeling
	}
	// Prompt save
	fs := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
		if err != nil || wc == nil {
			return
		}
		defer wc.Close()
		_ = png.Encode(wc, out)
	}, state.window)
	fs.SetFileName("iqm_all_charts.png")
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
	prefs.SetBool("crosshair", state.crosshairEnabled)
	prefs.SetBool("showHints", state.showHints)
	// (removed: pctl prefs)
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
		state.useRelative = strings.EqualFold(state.yScaleMode, "relative")
		if state.useRelative {
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
	state.crosshairEnabled = prefs.BoolWithFallback("crosshair", state.crosshairEnabled)
	if tabs != nil {
		idx := prefs.IntWithFallback("selectedTabIndex", 0)
		if idx >= 0 && idx < len(tabs.Items) {
			tabs.SelectIndex(idx)
		}
	}
	state.showHints = prefs.BoolWithFallback("showHints", state.showHints)
	// (removed: pctl prefs)
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

// crosshairOverlay draws a simple crosshair on top of a chart image when enabled.
// It tracks mouse position and shows a small label near the cursor with the pixel coordinates.
type crosshairOverlay struct {
	widget.BaseWidget
	state    *uiState
	enabled  bool
	mode     string // "speed", "ttfb", "error", "jitter", "cov", "pctl_overall", "pctl_ipv4", "pctl_ipv6"
	mouse    fyne.Position
	hovering bool
}

func newCrosshairOverlay(state *uiState, mode string) *crosshairOverlay {
	c := &crosshairOverlay{state: state, enabled: state != nil && state.crosshairEnabled, mode: mode}
	c.ExtendBaseWidget(c)
	return c
}

func (c *crosshairOverlay) CreateRenderer() fyne.WidgetRenderer {
	// background to ensure full hit-area for hover events
	bg := canvas.NewRectangle(color.RGBA{R: 0, G: 0, B: 0, A: 0})
	lineV := canvas.NewLine(color.RGBA{R: 200, G: 200, B: 200, A: 220})
	lineV.StrokeWidth = 1.0
	lineH := canvas.NewLine(color.RGBA{R: 200, G: 200, B: 200, A: 220})
	lineH.StrokeWidth = 1.0
	dot := canvas.NewCircle(color.RGBA{R: 240, G: 240, B: 240, A: 220})
	dot.StrokeColor = color.RGBA{R: 0, G: 0, B: 0, A: 0}
	dot.StrokeWidth = 0
	label := widget.NewRichText()
	label.Wrapping = fyne.TextWrapOff
	label.Segments = []widget.RichTextSegment{}
	labelBG := canvas.NewRectangle(color.RGBA{R: 0, G: 0, B: 0, A: 170})
	// No axis marker to avoid misaligned highlighting; keep it simple and accurate
	objs := []fyne.CanvasObject{bg, lineV, lineH, dot, labelBG, label}
	r := &crosshairRenderer{c: c, bg: bg, lineV: lineV, lineH: lineH, dot: dot, labelBG: labelBG, label: label, objs: objs}
	return r
}

type crosshairRenderer struct {
	c     *crosshairOverlay
	bg    *canvas.Rectangle
	lineV *canvas.Line
	lineH *canvas.Line
	dot   *canvas.Circle
	// axisMarker removed
	labelBG *canvas.Rectangle
	label   *widget.RichText
	objs    []fyne.CanvasObject
}

func (r *crosshairRenderer) Destroy() {}
func (r *crosshairRenderer) Layout(size fyne.Size) {
	if r.c == nil {
		return
	}
	if r.bg != nil {
		r.bg.Resize(size)
		r.bg.Move(fyne.NewPos(0, 0))
	}
	if !r.c.enabled || !r.c.hovering {
		// move lines out of view
		r.lineV.Position1 = fyne.NewPos(-10, -10)
		r.lineV.Position2 = fyne.NewPos(-10, -10)
		r.lineH.Position1 = fyne.NewPos(-10, -10)
		r.lineH.Position2 = fyne.NewPos(-10, -10)
		r.dot.Move(fyne.NewPos(-10, -10))
		r.label.Move(fyne.NewPos(-1000, -1000))
		if r.labelBG != nil {
			r.labelBG.Resize(fyne.NewSize(0, 0))
			r.labelBG.Move(fyne.NewPos(-1000, -1000))
		}
		return
	}
	x := r.c.mouse.X
	y := r.c.mouse.Y
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	if x > size.Width {
		x = size.Width
	}
	if y > size.Height {
		y = size.Height
	}
	// Prepare data for nearest index using actual drawn image rect (ImageFillContain aware)
	rows := filteredSummaries(r.c.state)
	n := len(rows)
	// Determine the underlying image size and the drawn rectangle inside this overlay
	var imgW, imgH float32
	var drawX, drawY, drawW, drawH, scale float32
	if r.c != nil && r.c.state != nil {
		var imgCanvas *canvas.Image
		switch r.c.mode {
		case "speed":
			imgCanvas = r.c.state.speedImgCanvas
		case "ttfb":
			imgCanvas = r.c.state.ttfbImgCanvas
		case "pctl_overall":
			imgCanvas = r.c.state.pctlOverallImg
		case "pctl_ipv4":
			imgCanvas = r.c.state.pctlIPv4Img
		case "pctl_ipv6":
			imgCanvas = r.c.state.pctlIPv6Img
		case "tpctl_overall":
			imgCanvas = r.c.state.tpctlOverallImg
		case "tpctl_ipv4":
			imgCanvas = r.c.state.tpctlIPv4Img
		case "tpctl_ipv6":
			imgCanvas = r.c.state.tpctlIPv6Img
		case "error":
			imgCanvas = r.c.state.errImgCanvas
		case "jitter":
			imgCanvas = r.c.state.jitterImgCanvas
		case "cov":
			imgCanvas = r.c.state.covImgCanvas
		case "plateau_count":
			imgCanvas = r.c.state.plCountImgCanvas
		case "plateau_longest":
			imgCanvas = r.c.state.plLongestImgCanvas
		case "plateau_stable":
			imgCanvas = r.c.state.plStableImgCanvas
		case "cache_hit":
			imgCanvas = r.c.state.cacheImgCanvas
		case "proxy_suspected":
			imgCanvas = r.c.state.proxyImgCanvas
		case "warm_cache":
			imgCanvas = r.c.state.warmCacheImgCanvas
		}
		if imgCanvas != nil && imgCanvas.Image != nil {
			b := imgCanvas.Image.Bounds()
			imgW = float32(b.Dx())
			imgH = float32(b.Dy())
		}
	}
	if imgW <= 0 || imgH <= 0 {
		imgW, imgH = float32(size.Width), float32(size.Height)
	}
	// Compute contain scaling
	if imgW > 0 && imgH > 0 {
		sx := float32(size.Width) / imgW
		sy := float32(size.Height) / imgH
		scale = sx
		if sy < sx {
			scale = sy
		}
		drawW = imgW * scale
		drawH = imgH * scale
		drawX = (float32(size.Width) - drawW) / 2
		drawY = (float32(size.Height) - drawH) / 2
	}
	// Hide crosshair when cursor is outside drawn image rect (contain-fit area)
	if !(float32(x) >= drawX && float32(x) <= drawX+drawW && float32(y) >= drawY && float32(y) <= drawY+drawH) {
		r.lineV.Position1 = fyne.NewPos(-10, -10)
		r.lineV.Position2 = fyne.NewPos(-10, -10)
		r.lineH.Position1 = fyne.NewPos(-10, -10)
		r.lineH.Position2 = fyne.NewPos(-10, -10)
		r.dot.Move(fyne.NewPos(-10, -10))
		if r.labelBG != nil {
			r.labelBG.Resize(fyne.NewSize(0, 0))
			r.labelBG.Move(fyne.NewPos(-1000, -1000))
		}
		r.label.Move(fyne.NewPos(-1000, -1000))
		return
	}
	// chart paddings used when rendering the image (in image pixel space)
	leftPadImg, rightPadImg := float32(16), float32(12)
	plotWImg := imgW - leftPadImg - rightPadImg
	if plotWImg < 1 {
		plotWImg = imgW
	}
	// Build X positions per point in image pixel space, then map to overlay space
	idx := 0
	// cx removed, we follow mouse for vertical line
	if n > 0 && plotWImg > 0 {
		pxView := make([]float32, n)
		timeMode, times, _, _ := buildXAxis(rows, r.c.state.xAxisMode)
		if timeMode {
			minT := times[0]
			maxT := times[0]
			for _, t := range times[1:] {
				if t.Before(minT) {
					minT = t
				}
				if t.After(maxT) {
					maxT = t
				}
			}
			span := maxT.Sub(minT)
			for i, t := range times {
				var fx float64
				if span > 0 {
					fx = float64(t.Sub(minT)) / float64(span)
				} else {
					fx = 0
				}
				pxImg := leftPadImg + float32(fx)*plotWImg
				pxView[i] = drawX + pxImg*scale
			}
		} else {
			for i := 0; i < n; i++ {
				pxImg := leftPadImg + plotWImg*(float32(i)+0.5)/float32(n)
				pxView[i] = drawX + pxImg*scale
			}
		}
		// Nearest by pixel distance in overlay coords
		bestD := float32(math.MaxFloat32)
		mx := float32(x)
		for i := 0; i < n; i++ {
			d := float32(math.Abs(float64(pxView[i] - mx)))
			if d < bestD {
				bestD = d
				idx = i
				// keep idx only; vertical line follows mouse
			}
		}
	}
	// vertical line follows mouse to avoid false precision when scaling is applied
	r.lineV.Position1 = fyne.NewPos(float32(x), 0)
	r.lineV.Position2 = fyne.NewPos(float32(x), size.Height)
	// horizontal line follows mouse Y
	r.lineH.Position1 = fyne.NewPos(0, y)
	r.lineH.Position2 = fyne.NewPos(size.Width, y)
	// dot at intersection
	r.dot.Resize(fyne.NewSize(6, 6))
	r.dot.Move(fyne.NewPos(x-3, y-3))
	// Draw a short underline marker at the bottom axis to indicate the active tick
	// no axis underline marker
	// Determine nearest data index and show values
	if n > 0 && size.Width > 0 {
		bs := rows[idx]
		// X label by mode
		var xLabel string
		switch r.c.state.xAxisMode {
		case "run_tag":
			xLabel = bs.RunTag
		case "time":
			t := parseRunTagTime(bs.RunTag)
			if !t.IsZero() {
				xLabel = t.Format("01-02 15:04:05")
			} else {
				xLabel = bs.RunTag
			}
		default:
			xLabel = fmt.Sprintf("Batch %d", idx+1)
		}
		var lines []string
		lines = append(lines, xLabel)
		switch r.c.mode {
		case "speed":
			unit, factor := speedUnitNameAndFactor(r.c.state.speedUnit)
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.1f %s", bs.AvgSpeed*factor, unit))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.1f %s", bs.IPv4.AvgSpeed*factor, unit))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.1f %s", bs.IPv6.AvgSpeed*factor, unit))
			}
		case "ttfb":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.0f ms", bs.AvgTTFB))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.0f ms", bs.IPv4.AvgTTFB))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.0f ms", bs.IPv6.AvgTTFB))
			}
		case "error":
			// percentage values
			if r.c.state.showOverall && bs.Lines > 0 {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", float64(bs.ErrorLines)/float64(bs.Lines)*100.0))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil && bs.IPv4.Lines > 0 {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", float64(bs.IPv4.ErrorLines)/float64(bs.IPv4.Lines)*100.0))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil && bs.IPv6.Lines > 0 {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", float64(bs.IPv6.ErrorLines)/float64(bs.IPv6.Lines)*100.0))
			}
		case "jitter":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", bs.AvgJitterPct))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", bs.IPv4.AvgJitterPct))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", bs.IPv6.AvgJitterPct))
			}
		case "cov":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", bs.AvgCoefVariationPct))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", bs.IPv4.AvgCoefVariationPct))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", bs.IPv6.AvgCoefVariationPct))
			}
		case "pctl_overall":
			unit, factor := speedUnitNameAndFactor(r.c.state.speedUnit)
			lines = append(lines, fmt.Sprintf("P50: %.1f %s", bs.AvgP50Speed*factor, unit))
			lines = append(lines, fmt.Sprintf("P90: %.1f %s", bs.AvgP90Speed*factor, unit))
			lines = append(lines, fmt.Sprintf("P95: %.1f %s", bs.AvgP95Speed*factor, unit))
			lines = append(lines, fmt.Sprintf("P99: %.1f %s", bs.AvgP99Speed*factor, unit))
		case "pctl_ipv4":
			unit, factor := speedUnitNameAndFactor(r.c.state.speedUnit)
			if bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("P50: %.1f %s", bs.IPv4.AvgP50Speed*factor, unit))
				lines = append(lines, fmt.Sprintf("P90: %.1f %s", bs.IPv4.AvgP90Speed*factor, unit))
				lines = append(lines, fmt.Sprintf("P95: %.1f %s", bs.IPv4.AvgP95Speed*factor, unit))
				lines = append(lines, fmt.Sprintf("P99: %.1f %s", bs.IPv4.AvgP99Speed*factor, unit))
			} else {
				lines = append(lines, "No IPv4 data")
			}
		case "pctl_ipv6":
			unit, factor := speedUnitNameAndFactor(r.c.state.speedUnit)
			if bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("P50: %.1f %s", bs.IPv6.AvgP50Speed*factor, unit))
				lines = append(lines, fmt.Sprintf("P90: %.1f %s", bs.IPv6.AvgP90Speed*factor, unit))
				lines = append(lines, fmt.Sprintf("P95: %.1f %s", bs.IPv6.AvgP95Speed*factor, unit))
				lines = append(lines, fmt.Sprintf("P99: %.1f %s", bs.IPv6.AvgP99Speed*factor, unit))
			} else {
				lines = append(lines, "No IPv6 data")
			}
		case "tpctl_overall":
			lines = append(lines, fmt.Sprintf("P50: %.0f ms", bs.AvgP50TTFBMs))
			lines = append(lines, fmt.Sprintf("P90: %.0f ms", bs.AvgP90TTFBMs))
			lines = append(lines, fmt.Sprintf("P95: %.0f ms", bs.AvgP95TTFBMs))
			lines = append(lines, fmt.Sprintf("P99: %.0f ms", bs.AvgP99TTFBMs))
		case "tpctl_ipv4":
			if bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("P50: %.0f ms", bs.IPv4.AvgP50TTFBMs))
				lines = append(lines, fmt.Sprintf("P90: %.0f ms", bs.IPv4.AvgP90TTFBMs))
				lines = append(lines, fmt.Sprintf("P95: %.0f ms", bs.IPv4.AvgP95TTFBMs))
				lines = append(lines, fmt.Sprintf("P99: %.0f ms", bs.IPv4.AvgP99TTFBMs))
			} else {
				lines = append(lines, "No IPv4 data")
			}
		case "tpctl_ipv6":
			if bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("P50: %.0f ms", bs.IPv6.AvgP50TTFBMs))
				lines = append(lines, fmt.Sprintf("P90: %.0f ms", bs.IPv6.AvgP90TTFBMs))
				lines = append(lines, fmt.Sprintf("P95: %.0f ms", bs.IPv6.AvgP95TTFBMs))
				lines = append(lines, fmt.Sprintf("P99: %.0f ms", bs.IPv6.AvgP99TTFBMs))
			} else {
				lines = append(lines, "No IPv6 data")
			}
		case "plateau_count":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f", bs.AvgPlateauCount))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f", bs.IPv4.AvgPlateauCount))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f", bs.IPv6.AvgPlateauCount))
			}
		case "plateau_longest":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.0f ms", bs.AvgLongestPlateau))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.0f ms", bs.IPv4.AvgLongestPlateau))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.0f ms", bs.IPv6.AvgLongestPlateau))
			}
		case "plateau_stable":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", bs.PlateauStableRatePct))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", bs.IPv4.PlateauStableRatePct))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", bs.IPv6.PlateauStableRatePct))
			}
		case "cache_hit":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", bs.CacheHitRatePct))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", bs.IPv4.CacheHitRatePct))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", bs.IPv6.CacheHitRatePct))
			}
		case "proxy_suspected":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", bs.ProxySuspectedRatePct))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", bs.IPv4.ProxySuspectedRatePct))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", bs.IPv6.ProxySuspectedRatePct))
			}
		case "warm_cache":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", bs.WarmCacheSuspectedRatePct))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", bs.IPv4.WarmCacheSuspectedRatePct))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", bs.IPv6.WarmCacheSuspectedRatePct))
			}
		}
		r.label.Segments = []widget.RichTextSegment{&widget.TextSegment{Text: strings.Join(lines, "\n")}}
	} else {
		r.label.Segments = nil
	}
	r.label.Refresh()
	// draw a semi-transparent background to improve readability
	pad := float32(6)
	ts := r.label.MinSize()
	bgW := ts.Width + 2*pad
	bgH := ts.Height + 2*pad
	tx, ty := x+8, y+8
	if tx+bgW > size.Width {
		tx = size.Width - bgW
	}
	if ty+bgH > size.Height {
		ty = size.Height - bgH
	}
	if len(r.label.Segments) == 0 {
		r.labelBG.Resize(fyne.NewSize(0, 0))
		r.labelBG.Move(fyne.NewPos(-1000, -1000))
		r.label.Move(fyne.NewPos(-1000, -1000))
	} else {
		r.labelBG.Resize(fyne.NewSize(bgW, bgH))
		r.labelBG.Move(fyne.NewPos(tx, ty))
		r.label.Move(fyne.NewPos(tx+pad, ty+pad))
	}
}
func (r *crosshairRenderer) MinSize() fyne.Size           { return fyne.NewSize(10, 10) }
func (r *crosshairRenderer) Objects() []fyne.CanvasObject { return r.objs }
func (r *crosshairRenderer) Refresh() {
	// Recompute positions based on latest mouse and enabled state
	r.Layout(r.c.Size())
	// Refresh primitives
	if r.bg != nil {
		r.bg.Refresh()
	}
	// Update colors to match theme each refresh
	r.lineV.StrokeColor = theme.Color(theme.ColorNameDisabled)
	r.lineV.StrokeWidth = 1
	r.lineH.StrokeColor = theme.Color(theme.ColorNameDisabled)
	r.lineH.StrokeWidth = 1
	// no axis marker
	r.lineV.Refresh()
	r.lineH.Refresh()
	r.dot.Refresh()
	// no axis marker
	if r.labelBG != nil {
		r.labelBG.Refresh()
	}
	r.label.Refresh()
}

// Implement mouse movement handling
func (c *crosshairOverlay) MouseMoved(ev *desktop.MouseEvent) {
	if !c.enabled {
		return
	}
	c.hovering = true
	c.mouse = ev.Position
	c.Refresh()
}
func (c *crosshairOverlay) MouseIn(ev *desktop.MouseEvent) { c.hovering = true; c.Refresh() }
func (c *crosshairOverlay) MouseOut()                      { c.hovering = false; c.Refresh() }

// Assert that crosshairOverlay implements desktop.Hoverable
var _ desktop.Hoverable = (*crosshairOverlay)(nil)
