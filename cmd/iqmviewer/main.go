package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	chart "github.com/wcharczuk/go-chart/v2"
	"github.com/wcharczuk/go-chart/v2/drawing"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

// screenshotThemeGlobal holds the effective theme used for charts/screenshots.
// Values: "dark" or "light".
var screenshotThemeGlobal = "dark"

// screenshotThemeMode is the user's selection: "auto" (default on first run), "dark", or "light".
var screenshotThemeMode = "auto"

// screenshotWidthOverride lets tests force a specific chart width in headless mode (no window).
// When > 0 and state.window==nil, chartSize will return this width. Normal app runs ignore this.
var screenshotWidthOverride = 0

// resolveTheme maps a user-facing mode to an effective chart theme.
func resolveTheme(mode string, app fyne.App) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "dark" {
		return "dark"
	}
	if m == "light" {
		return "light"
	}
	// auto or any other value: follow system preference when available
	if isSystemDark() {
		return "dark"
	}
	return "light"
}

// Currently supports macOS via `defaults read -g AppleInterfaceStyle`.
func isSystemDark() bool {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("defaults", "read", "-g", "AppleInterfaceStyle").Output()
		if err != nil {
			return false
		}
		return strings.Contains(strings.ToLower(string(out)), "dark")
	}
	return false
}

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

	// transport/protocol charts
	protocolMixImgCanvas         *canvas.Image // HTTP protocol mix (%)
	protocolAvgSpeedImgCanvas    *canvas.Image // Avg speed by HTTP protocol
	protocolStallRateImgCanvas   *canvas.Image // Stall rate by HTTP protocol (%)
	protocolErrorRateImgCanvas   *canvas.Image // Error rate by HTTP protocol (%)
	protocolErrorShareImgCanvas  *canvas.Image // Error share by HTTP protocol (%) – sums to ~100%
	protocolPartialRateImgCanvas *canvas.Image // Partial body rate by HTTP protocol (%)
	tlsVersionMixImgCanvas       *canvas.Image // TLS version mix (%)
	alpnMixImgCanvas             *canvas.Image // ALPN mix (%)
	chunkedRateImgCanvas         *canvas.Image // Chunked transfer rate (%)

	// Local throughput self-test chart
	selfTestImgCanvas *canvas.Image // Local loopback throughput baseline (kbps -> chosen unit)

	// internal guards
	initializing bool

	// new charts
	tailRatioImgCanvas     *canvas.Image // P99/P50 Speed ratio
	ttfbTailRatioImgCanvas *canvas.Image // P95/P50 TTFB ratio
	speedDeltaImgCanvas    *canvas.Image // IPv6-IPv4 speed delta
	ttfbDeltaImgCanvas     *canvas.Image // IPv4-IPv6 ttfb delta (positive=IPv6 better)
	speedDeltaPctImgCanvas *canvas.Image // IPv6-IPv4 speed delta (%) vs IPv4
	ttfbDeltaPctImgCanvas  *canvas.Image // (IPv4-IPv6) ttfb delta (%) vs IPv6
	slaSpeedImgCanvas      *canvas.Image // SLA compliance for speed
	slaTTFBImgCanvas       *canvas.Image // SLA compliance for TTFB
	slaSpeedDeltaImgCanvas *canvas.Image // SLA compliance delta (IPv6−IPv4) in pp
	slaTTFBDeltaImgCanvas  *canvas.Image // SLA compliance delta (IPv6−IPv4) in pp
	// tail/latency depth extra
	tpctlP95GapImgCanvas *canvas.Image // TTFB P95−P50 gap (ms)

	// stability & quality charts
	lowSpeedImgCanvas    *canvas.Image // Low-Speed Time Share (%)
	stallRateImgCanvas   *canvas.Image // Stall Rate (%)
	pretffbImgCanvas     *canvas.Image // Pre-TTFB Stall Rate (%)
	stallTimeImgCanvas   *canvas.Image // Avg Stall Time (ms)
	stallCountImgCanvas  *canvas.Image // Stalled Requests Count (interim)
	partialBodyImgCanvas *canvas.Image // Partial Body Rate (%)

	// connection setup breakdown charts
	setupDNSImgCanvas  *canvas.Image // Avg DNS time (ms)
	setupConnImgCanvas *canvas.Image // Avg TCP connect (ms)
	setupTLSImgCanvas  *canvas.Image // Avg TLS handshake (ms)
	// overlays for setup charts
	setupDNSOverlay  *crosshairOverlay
	setupConnOverlay *crosshairOverlay
	setupTLSOverlay  *crosshairOverlay

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
	// overlays for transport/protocol charts
	protocolMixOverlay         *crosshairOverlay
	protocolAvgSpeedOverlay    *crosshairOverlay
	protocolStallRateOverlay   *crosshairOverlay
	protocolErrorRateOverlay   *crosshairOverlay
	protocolErrorShareOverlay  *crosshairOverlay
	protocolPartialRateOverlay *crosshairOverlay
	tlsVersionMixOverlay       *crosshairOverlay
	alpnMixOverlay             *crosshairOverlay
	chunkedRateOverlay         *crosshairOverlay
	// overlays for new charts
	tailRatioOverlay     *crosshairOverlay
	ttfbTailRatioOverlay *crosshairOverlay
	speedDeltaOverlay    *crosshairOverlay
	ttfbDeltaOverlay     *crosshairOverlay
	speedDeltaPctOverlay *crosshairOverlay
	ttfbDeltaPctOverlay  *crosshairOverlay
	slaSpeedOverlay      *crosshairOverlay
	slaTTFBOverlay       *crosshairOverlay
	slaSpeedDeltaOverlay *crosshairOverlay
	slaTTFBDeltaOverlay  *crosshairOverlay
	// extra overlay
	tpctlP95GapOverlay *crosshairOverlay

	// self-test overlay
	selfTestOverlay *crosshairOverlay

	// stability overlays
	lowSpeedOverlay    *crosshairOverlay
	stallRateOverlay   *crosshairOverlay
	pretffbOverlay     *crosshairOverlay
	stallTimeOverlay   *crosshairOverlay
	stallCountOverlay  *crosshairOverlay
	partialBodyOverlay *crosshairOverlay

	// section containers for conditional visibility
	pretffbBlock    *fyne.Container // wraps separator + Pre‑TTFB chart section for hide/show
	pretffbSection  *fyne.Container // inner chart section (header + stack)
	showPreTTFB     bool            // user preference to include Pre‑TTFB chart in UI
	autoHidePreTTFB bool            // if true, auto-hide Pre‑TTFB when metric is zero across all batches

	// SLA thresholds (configurable via UI)
	slaSpeedThresholdKbps int // default 10000 (10 Mbps)
	slaTTFBThresholdMs    int // default 200 ms

	// Low-speed threshold for Low-Speed Time Share metric (kbps)
	lowSpeedThresholdKbps int // default 1000

	// containers
	pctlGrid *fyne.Container

	// crosshair
	crosshairEnabled    bool
	speedOverlay        *crosshairOverlay
	ttfbOverlay         *crosshairOverlay
	pctlOverallOverlay  *crosshairOverlay
	pctlIPv4Overlay     *crosshairOverlay
	pctlIPv6Overlay     *crosshairOverlay
	tpctlOverallOverlay *crosshairOverlay
	tpctlIPv4Overlay    *crosshairOverlay
	tpctlIPv6Overlay    *crosshairOverlay
	lastSpeedPopup      *widget.PopUp
	lastTTFBPopup       *widget.PopUp

	// chart hints toggle
	showHints bool

	// option to overlay legacy pre-resolve DNS timing (dns_time_ms) on DNS chart
	showDNSLegacy bool

	// prefs
	speedUnit string // "kbps", "kBps", "Mbps", "MBps", "Gbps", "GBps"

	// rolling overlays
	showRolling     bool // show rolling mean line on Speed/TTFB
	showRollingBand bool // show translucent ±1σ band around rolling mean
	rollingWindow   int  // default 7

	// charts registry and search
	chartsScroll *container.Scroll
	chartRefs    []chartRef
	findEntry    *widget.Entry
	findCountLbl *widget.Label
	findIndex    int
	findMatches  []int
}

// chartRef tracks a chart section for search/navigation
type chartRef struct {
	title   string
	section *fyne.Container
}

// makeChartSection composes a header row (title + info button) and the stacked image+overlay
func makeChartSection(state *uiState, title string, help string, stack *fyne.Container) *fyne.Container {
	titleLbl := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	infoBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		// Show help in a dialog with wrapping
		dlg := dialog.NewCustom(title+" – Info", "Close", container.NewVScroll(widget.NewLabel(help)), fyne.CurrentApp().Driver().AllWindows()[0])
		dlg.Resize(fyne.NewSize(520, 380))
		dlg.Show()
	})
	infoBtn.Importance = widget.LowImportance
	header := container.New(layout.NewHBoxLayout(), titleLbl, layout.NewSpacer(), infoBtn)
	sec := container.NewVBox(header, stack)
	if state != nil {
		state.chartRefs = append(state.chartRefs, chartRef{title: title, section: sec})
	}
	return sec
}

// updateFindMatches recomputes the matching chart indices based on the findEntry text
func updateFindMatches(state *uiState) {
	if state == nil {
		return
	}
	query := ""
	if state.findEntry != nil {
		query = strings.TrimSpace(strings.ToLower(state.findEntry.Text))
	}
	state.findMatches = state.findMatches[:0]
	if query == "" {
		state.findIndex = 0
		if state.findCountLbl != nil {
			state.findCountLbl.SetText("")
		}
		return
	}
	for i, r := range state.chartRefs {
		if strings.Contains(strings.ToLower(r.title), query) {
			state.findMatches = append(state.findMatches, i)
		}
	}
	if len(state.findMatches) == 0 {
		state.findIndex = 0
		if state.findCountLbl != nil {
			state.findCountLbl.SetText("0/0")
		}
		return
	}
	if state.findIndex >= len(state.findMatches) || state.findIndex < 0 {
		state.findIndex = 0
	}
	if state.findCountLbl != nil {
		state.findCountLbl.SetText(fmt.Sprintf("%d/%d", state.findIndex+1, len(state.findMatches)))
	}
}

func findScrollToCurrent(state *uiState) {
	if state == nil || state.chartsScroll == nil || len(state.findMatches) == 0 || state.findIndex < 0 || state.findIndex >= len(state.findMatches) {
		return
	}
	idx := state.findMatches[state.findIndex]
	if idx < 0 || idx >= len(state.chartRefs) {
		return
	}
	ref := state.chartRefs[idx]
	if ref.section != nil {
		// Approximate vertical offset by summing previous sections' heights
		var offY float32
		for i := 0; i < idx && i < len(state.chartRefs); i++ {
			if state.chartRefs[i].section != nil {
				h := state.chartRefs[i].section.MinSize().Height
				offY += h + 8 // include separator/spacing estimate
			}
		}
		// Try to use ScrollToOffset if available
		type scroller interface{ ScrollToOffset(pos fyne.Position) }
		if s, ok := any(state.chartsScroll).(scroller); ok {
			s.ScrollToOffset(fyne.NewPos(0, offY))
		} else {
			// Fallback: crude heuristic based on position in list
			if float64(idx) > float64(len(state.chartRefs))/2.0 {
				state.chartsScroll.ScrollToBottom()
			} else {
				state.chartsScroll.ScrollToTop()
			}
		}
	}
}

func findNext(state *uiState) {
	if state == nil || len(state.findMatches) == 0 {
		return
	}
	state.findIndex = (state.findIndex + 1) % len(state.findMatches)
	if state.findCountLbl != nil {
		state.findCountLbl.SetText(fmt.Sprintf("%d/%d", state.findIndex+1, len(state.findMatches)))
	}
	findScrollToCurrent(state)
}

func findPrev(state *uiState) {
	if state == nil || len(state.findMatches) == 0 {
		return
	}
	state.findIndex--
	if state.findIndex < 0 {
		state.findIndex = len(state.findMatches) - 1
	}
	if state.findCountLbl != nil {
		state.findCountLbl.SetText(fmt.Sprintf("%d/%d", state.findIndex+1, len(state.findMatches)))
	}
	findScrollToCurrent(state)
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
	var shots bool
	var shotsOut string
	var shotsSituation string
	var shotsRollingWindow int
	var shotsBand bool
	var shotsLowSpeedThreshKbps int
	var shotsBatches int
	var shotsTheme string
	var shotsVariants string
	var shotsDNSLegacy bool
	var shotsSelfTest bool
	var shotsIncludePreTTFB bool
	var selfTest bool
	var showPretffbCLI string
	flag.StringVar(&fileFlag, "file", "", "Path to monitor_results.jsonl")
	flag.BoolVar(&shots, "screenshot", false, "Run in headless screenshot mode and save sample charts to --screenshot-outdir")
	flag.StringVar(&shotsOut, "screenshot-outdir", "docs/images", "Directory to write screenshots into (created if missing)")
	flag.StringVar(&shotsSituation, "screenshot-situation", "All", "Situation label to render (use 'All' for all situations)")
	flag.IntVar(&shotsRollingWindow, "screenshot-rolling-window", 7, "Rolling window N for overlays")
	flag.BoolVar(&shotsBand, "screenshot-rolling-band", true, "Whether to show the ±1σ band in screenshots")
	flag.IntVar(&shotsLowSpeedThreshKbps, "screenshot-low-speed-threshold-kbps", 1000, "Low-Speed Threshold (kbps) used for Low-Speed Time Share in screenshots")
	flag.IntVar(&shotsBatches, "screenshot-batches", 50, "How many recent batches to include in screenshots")
	flag.StringVar(&shotsTheme, "screenshot-theme", "auto", "Screenshot theme: 'auto', 'dark', or 'light'")
	flag.StringVar(&shotsVariants, "screenshot-variants", "averages", "Which extra variants to render: 'none' or 'averages'")
	flag.BoolVar(&shotsDNSLegacy, "screenshot-dns-legacy", false, "If true, overlay legacy dns_time_ms as dashed line on DNS chart in screenshots")
	flag.BoolVar(&shotsSelfTest, "screenshot-selftest", true, "Include the Local Throughput Self-Test chart in screenshots")
	flag.BoolVar(&shotsIncludePreTTFB, "screenshot-pretffb", true, "Include Pre‑TTFB Stall Rate chart if data is present")
	flag.BoolVar(&selfTest, "selftest-speed", true, "Run a quick local throughput self-test on startup (loopback)")
	flag.StringVar(&showPretffbCLI, "show-pretffb", "", "Show Pre‑TTFB chart on launch (true|false); persists preference")
	flag.Parse()

	if selfTest {
		kbps, err := monitor.LocalMaxSpeedProbe(300 * time.Millisecond)
		if err != nil {
			fmt.Println("[selftest] local throughput probe error:", err)
		} else {
			_, factor := speedUnitNameAndFactor("Mbps")
			fmt.Printf("[selftest] local throughput: %.1f Mbps (%.0f kbps)\n", kbps*factor, kbps)
			monitor.SetLocalSelfTestKbps(kbps)
		}
	}

	// Headless screenshots mode: no UI, just render and write images.
	if shots {
		if err := RunScreenshotsMode(fileFlag, shotsOut, shotsSituation, shotsRollingWindow, shotsBand, shotsBatches, shotsLowSpeedThreshKbps, shotsVariants, shotsTheme, shotsDNSLegacy, shotsSelfTest, shotsIncludePreTTFB); err != nil {
			fmt.Fprintf(os.Stderr, "screenshot mode error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[viewer] screenshots written to:", shotsOut)
		return
	}

	a := app.NewWithID("com.iqm.viewer")
	a.Settings().SetTheme(&darkTheme{})
	w := a.NewWindow("IQM Viewer")
	w.Resize(fyne.NewSize(1100, 800))

	state := &uiState{
		app:             a,
		window:          w,
		filePath:        fileFlag,
		batchesN:        50,
		xAxisMode:       "batch",
		yScaleMode:      "absolute",
		showOverall:     true,
		showIPv4:        true,
		showIPv6:        true,
		speedUnit:       "kbps",
		showRolling:     true,
		showRollingBand: true,
		rollingWindow:   7,
	}
	// Sensible corporate defaults for SLA thresholds
	state.slaSpeedThresholdKbps = 10000 // 10 Mbps P50 speed target
	state.slaTTFBThresholdMs = 200      // 200 ms P95 TTFB target
	// Ensure crosshair preference is loaded before creating overlays/controls
	state.crosshairEnabled = a.Preferences().BoolWithFallback("crosshair", false)
	// Load showHints early so the checkbox reflects it on creation
	state.showHints = a.Preferences().BoolWithFallback("showHints", false)
	// Initialize DNS legacy overlay preference early (used by menus)
	state.showDNSLegacy = a.Preferences().BoolWithFallback("showDNSLegacy", false)
	// Initialize theme mode from preferences (default: auto). Resolve effective theme for charts.
	screenshotThemeMode = strings.ToLower(strings.TrimSpace(a.Preferences().StringWithFallback("screenshotThemeMode", "auto")))
	if screenshotThemeMode != "auto" && screenshotThemeMode != "light" && screenshotThemeMode != "dark" {
		screenshotThemeMode = "auto"
	}
	screenshotThemeGlobal = resolveTheme(screenshotThemeMode, a)
	// Load Pre‑TTFB chart visibility preference (default: true)
	state.showPreTTFB = a.Preferences().BoolWithFallback("showPreTTFB", true)
	// Auto-hide Pre‑TTFB when metric is all zero (default: false)
	state.autoHidePreTTFB = a.Preferences().BoolWithFallback("autoHidePreTTFB", false)
	// If CLI provided, override and persist
	if v := strings.ToLower(strings.TrimSpace(showPretffbCLI)); v == "true" || v == "false" {
		state.showPreTTFB = (v == "true")
		savePrefs(state)
	}
	// (removed: pctlFamily/pctlCompare preferences)

	// top bar controls
	fileLabel := widget.NewLabel(truncatePath(state.filePath, 60))
	// (Speed Unit selection moved to Settings menu)

	// series toggles (callbacks assigned later, after canvases exist)
	overallChk := widget.NewCheck("Overall", nil)
	ipv4Chk := widget.NewCheck("IPv4", nil)
	ipv6Chk := widget.NewCheck("IPv6", nil)
	// (Crosshair checkbox removed from toolbar; use Settings → Crosshair)

	// (X-Axis and Y-Scale moved to Settings menu)

	// (removed: compare toggle)
	// (Hints toggle removed from toolbar; use Settings → Hints)

	// Situation selector (options filled after first load)
	sitSelect := widget.NewSelect([]string{}, func(v string) {
		if state.initializing {
			return
		}
		if strings.EqualFold(v, "all") {
			// Persist "All" literally so it survives restarts unambiguously
			state.situation = "All"
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

	// (Batches control moved to Settings menu)

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
	// Compute initial chart size to give all images full application width from the start
	_, ih := chartSize(state)
	state.speedImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.speedImgCanvas.FillMode = canvas.ImageFillStretch
	state.speedImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.ttfbImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.ttfbImgCanvas.FillMode = canvas.ImageFillStretch
	state.ttfbImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))

	// layout
	// top bar
	// (Low-speed threshold moved to Settings menu)

	// Rolling overlays controls
	if state.rollingWindow <= 0 {
		state.rollingWindow = 7
	}
	// (Rolling Window and Rolling toggles moved to Settings menu)

	// Find UI
	state.findEntry = widget.NewEntry()
	state.findEntry.SetPlaceHolder("Find chart…")
	state.findCountLbl = widget.NewLabel("")
	nextBtn := widget.NewButton("Next", func() { findNext(state) })
	prevBtn := widget.NewButton("Prev", func() { findPrev(state) })
	state.findEntry.OnChanged = func(string) {
		updateFindMatches(state)
	}
	state.findEntry.OnSubmitted = func(string) {
		findNext(state)
	}

	top := container.NewHBox(
		widget.NewButton("Open…", func() { openFileDialog(state, fileLabel) }),
		widget.NewButton("Reload", func() { loadAll(state, fileLabel) }),
		// (X-Axis and Y-Scale moved to Settings menu)
		// (SLA, Low-Speed Threshold, Rolling Window moved to Settings menu)
		widget.NewLabel("Situation:"), sitSelect,
		// (Batches moved to Settings menu)
		overallChk, ipv4Chk, ipv6Chk,
		layout.NewSpacer(),
		widget.NewLabel("Find:"), state.findEntry, prevBtn, nextBtn, state.findCountLbl,
		widget.NewLabel("File:"), fileLabel,
	)
	// Make the toolbar horizontally scrollable so it doesn't enforce a large minimum window width
	topScroll := container.NewHScroll(top)
	// charts stacked vertically with scroll for future additions
	// ensure reasonable minimum heights for readability
	// Use full chart width instead of hardcoded sizes so all graphs are 100% width
	state.speedImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.ttfbImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	// overlays for crosshair
	state.speedOverlay = newCrosshairOverlay(state, "speed")
	state.ttfbOverlay = newCrosshairOverlay(state, "ttfb")
	// new percentiles + error charts placeholders (stacked view only)
	// compare view canvases (vertical stack: Overall, IPv4, IPv6)
	state.pctlOverallImg = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.pctlOverallImg.FillMode = canvas.ImageFillStretch
	state.pctlIPv4Img = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.pctlIPv4Img.FillMode = canvas.ImageFillStretch
	state.pctlIPv6Img = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.pctlIPv6Img.FillMode = canvas.ImageFillStretch
	// set initial min sizes to full chart size
	_, chh := chartSize(state)
	state.pctlOverallImg.SetMinSize(fyne.NewSize(0, float32(chh)))
	state.pctlIPv4Img.SetMinSize(fyne.NewSize(0, float32(chh)))
	state.pctlIPv6Img.SetMinSize(fyne.NewSize(0, float32(chh)))
	// Create overlays for percentiles charts
	state.pctlOverallOverlay = newCrosshairOverlay(state, "pctl_overall")
	state.pctlIPv4Overlay = newCrosshairOverlay(state, "pctl_ipv4")
	state.pctlIPv6Overlay = newCrosshairOverlay(state, "pctl_ipv6")
	// TTFB percentile canvases
	state.tpctlOverallImg = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tpctlOverallImg.FillMode = canvas.ImageFillStretch
	state.tpctlIPv4Img = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tpctlIPv4Img.FillMode = canvas.ImageFillStretch
	state.tpctlIPv6Img = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tpctlIPv6Img.FillMode = canvas.ImageFillStretch
	state.tpctlOverallImg.SetMinSize(fyne.NewSize(0, float32(chh)))
	state.tpctlIPv4Img.SetMinSize(fyne.NewSize(0, float32(chh)))
	state.tpctlIPv6Img.SetMinSize(fyne.NewSize(0, float32(chh)))
	// overlays for TTFB percentiles
	state.tpctlOverallOverlay = newCrosshairOverlay(state, "tpctl_overall")
	state.tpctlIPv4Overlay = newCrosshairOverlay(state, "tpctl_ipv4")
	state.tpctlIPv6Overlay = newCrosshairOverlay(state, "tpctl_ipv6")
	// Previously used a combined percentiles grid; now split into separate sections below.
	state.pctlGrid = nil
	state.errImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.errImgCanvas.FillMode = canvas.ImageFillStretch
	state.errImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	// overlay for error rate
	state.errOverlay = newCrosshairOverlay(state, "error")
	// jitter & coefficient of variation charts
	state.jitterImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.jitterImgCanvas.FillMode = canvas.ImageFillStretch
	state.jitterImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.jitterOverlay = newCrosshairOverlay(state, "jitter")
	state.covImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.covImgCanvas.FillMode = canvas.ImageFillStretch
	state.covImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.covOverlay = newCrosshairOverlay(state, "cov")
	// plateau charts
	state.plCountImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.plCountImgCanvas.FillMode = canvas.ImageFillStretch
	state.plCountImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.plCountOverlay = newCrosshairOverlay(state, "plateau_count")
	state.plLongestImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.plLongestImgCanvas.FillMode = canvas.ImageFillStretch
	state.plLongestImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.plLongestOverlay = newCrosshairOverlay(state, "plateau_longest")
	// plateau stability rate chart
	state.plStableImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.plStableImgCanvas.FillMode = canvas.ImageFillStretch
	state.plStableImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.plStableOverlay = newCrosshairOverlay(state, "plateau_stable")
	// cache/proxy/warm-cache rate charts
	state.cacheImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.cacheImgCanvas.FillMode = canvas.ImageFillStretch
	state.cacheImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.cacheOverlay = newCrosshairOverlay(state, "cache_hit")
	state.proxyImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.proxyImgCanvas.FillMode = canvas.ImageFillStretch
	state.proxyImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.proxyOverlay = newCrosshairOverlay(state, "proxy_suspected")
	state.warmCacheImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	// transport/protocol canvases
	state.protocolMixImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.protocolAvgSpeedImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.protocolStallRateImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.protocolErrorRateImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.protocolErrorShareImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.protocolPartialRateImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tlsVersionMixImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.alpnMixImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.chunkedRateImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.warmCacheImgCanvas.FillMode = canvas.ImageFillStretch
	state.warmCacheImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.protocolMixImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.protocolAvgSpeedImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.protocolStallRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.protocolErrorRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.protocolErrorShareImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.protocolPartialRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.tlsVersionMixImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.alpnMixImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.chunkedRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.warmCacheOverlay = newCrosshairOverlay(state, "warm_cache")
	// transport/protocol overlays
	state.protocolMixOverlay = newCrosshairOverlay(state, "protocol_mix")
	state.protocolAvgSpeedOverlay = newCrosshairOverlay(state, "protocol_avg_speed")
	state.protocolStallRateOverlay = newCrosshairOverlay(state, "protocol_stall_rate")
	state.protocolErrorRateOverlay = newCrosshairOverlay(state, "protocol_error_rate")
	state.protocolErrorShareOverlay = newCrosshairOverlay(state, "protocol_error_share")
	state.protocolPartialRateOverlay = newCrosshairOverlay(state, "protocol_partial_rate")
	state.tlsVersionMixOverlay = newCrosshairOverlay(state, "tls_version_mix")
	state.alpnMixOverlay = newCrosshairOverlay(state, "alpn_mix")
	state.chunkedRateOverlay = newCrosshairOverlay(state, "chunked_rate")

	// Self-test chart placeholder
	state.selfTestImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.selfTestImgCanvas.FillMode = canvas.ImageFillStretch
	state.selfTestImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.selfTestOverlay = newCrosshairOverlay(state, "selftest_speed")

	// new charts: tail heaviness (P99/P50), IPv6-IPv4 deltas, SLA compliance
	state.tailRatioImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tailRatioImgCanvas.FillMode = canvas.ImageFillStretch
	state.tailRatioImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.tailRatioOverlay = newCrosshairOverlay(state, "tail_ratio")

	// TTFB Tail Heaviness (P95/P50)
	state.ttfbTailRatioImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.ttfbTailRatioImgCanvas.FillMode = canvas.ImageFillStretch
	state.ttfbTailRatioImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.ttfbTailRatioOverlay = newCrosshairOverlay(state, "ttfb_tail_ratio")

	state.speedDeltaImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.speedDeltaImgCanvas.FillMode = canvas.ImageFillStretch
	state.speedDeltaImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.speedDeltaOverlay = newCrosshairOverlay(state, "speed_delta")

	state.ttfbDeltaImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.ttfbDeltaImgCanvas.FillMode = canvas.ImageFillStretch
	state.ttfbDeltaImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.ttfbDeltaOverlay = newCrosshairOverlay(state, "ttfb_delta")

	// Percent-based deltas
	state.speedDeltaPctImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.speedDeltaPctImgCanvas.FillMode = canvas.ImageFillStretch
	state.speedDeltaPctImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.speedDeltaPctOverlay = newCrosshairOverlay(state, "speed_delta_pct")

	state.ttfbDeltaPctImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.ttfbDeltaPctImgCanvas.FillMode = canvas.ImageFillStretch
	state.ttfbDeltaPctImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.ttfbDeltaPctOverlay = newCrosshairOverlay(state, "ttfb_delta_pct")

	state.slaSpeedImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.slaSpeedImgCanvas.FillMode = canvas.ImageFillStretch
	state.slaSpeedImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.slaSpeedOverlay = newCrosshairOverlay(state, "sla_speed")

	state.slaTTFBImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.slaTTFBImgCanvas.FillMode = canvas.ImageFillStretch
	state.slaTTFBImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.slaTTFBOverlay = newCrosshairOverlay(state, "sla_ttfb")

	// SLA delta charts (percentage points difference IPv6−IPv4)
	state.slaSpeedDeltaImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.slaSpeedDeltaImgCanvas.FillMode = canvas.ImageFillStretch
	state.slaSpeedDeltaImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.slaSpeedDeltaOverlay = newCrosshairOverlay(state, "sla_speed_delta")

	state.slaTTFBDeltaImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.slaTTFBDeltaImgCanvas.FillMode = canvas.ImageFillStretch
	state.slaTTFBDeltaImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.slaTTFBDeltaOverlay = newCrosshairOverlay(state, "sla_ttfb_delta")

	// TTFB P95−P50 Gap chart
	state.tpctlP95GapImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.tpctlP95GapImgCanvas.FillMode = canvas.ImageFillStretch
	state.tpctlP95GapImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.tpctlP95GapOverlay = newCrosshairOverlay(state, "ttfb_p95_gap")

	// Stability & quality placeholders
	state.lowSpeedImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.lowSpeedImgCanvas.FillMode = canvas.ImageFillStretch
	state.lowSpeedImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.lowSpeedOverlay = newCrosshairOverlay(state, "low_speed_share")
	state.stallRateImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.stallRateImgCanvas.FillMode = canvas.ImageFillStretch
	state.stallRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.stallRateOverlay = newCrosshairOverlay(state, "stall_rate")
	// Pre‑TTFB Stall Rate
	state.pretffbImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.pretffbImgCanvas.FillMode = canvas.ImageFillStretch
	state.pretffbImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.pretffbOverlay = newCrosshairOverlay(state, "pretffb_stall_rate")
	// Partial Body Rate
	state.partialBodyImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.partialBodyImgCanvas.FillMode = canvas.ImageFillStretch
	state.partialBodyImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.partialBodyOverlay = newCrosshairOverlay(state, "partial_body_rate")
	// Stalled Requests Count (interim)
	state.stallCountImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.stallCountImgCanvas.FillMode = canvas.ImageFillStretch
	state.stallCountImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.stallCountOverlay = newCrosshairOverlay(state, "stall_count")
	state.stallTimeImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.stallTimeImgCanvas.FillMode = canvas.ImageFillStretch
	state.stallTimeImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.stallTimeOverlay = newCrosshairOverlay(state, "stall_time")

	// Setup breakdown placeholders
	state.setupDNSImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.setupDNSImgCanvas.FillMode = canvas.ImageFillStretch
	state.setupDNSImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.setupDNSOverlay = newCrosshairOverlay(state, "setup_dns")
	state.setupConnImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.setupConnImgCanvas.FillMode = canvas.ImageFillStretch
	state.setupConnImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.setupConnOverlay = newCrosshairOverlay(state, "setup_conn")
	state.setupTLSImgCanvas = canvas.NewImageFromImage(image.NewRGBA(image.Rect(0, 0, 100, 60)))
	state.setupTLSImgCanvas.FillMode = canvas.ImageFillStretch
	state.setupTLSImgCanvas.SetMinSize(fyne.NewSize(0, float32(ih)))
	state.setupTLSOverlay = newCrosshairOverlay(state, "setup_tls")

	// Help text for charts (detailed). Mention X-Axis, Y-Scale and Situation controls and include references.
	axesTip := "\n\nTips:\n- X-Axis can be switched (Batch | RunTag | Time) from Settings → X-Axis.\n- Y-Scale can be toggled (Absolute | Relative) from Settings → Y-Scale.\n- Batches count is configurable in Settings → Batches.\n- Situation can be filtered via the toolbar selector (defaults to All). Exports include the active Situation in a bottom-right watermark.\n"
	helpSpeed := `Transfer Speed shows per-batch average throughput, optionally split by IP family (IPv4/IPv6).
- Useful for tracking overall performance trends over time or across runs.
- Pair with Speed Percentiles to understand variability not visible in averages.
- Rolling overlays: optional Rolling Mean and a translucent μ±1σ band computed over a sliding window of N batches (N = Rolling Window control). Larger N smooths more; the band visualizes variability (wider = more volatile). You can toggle the band independently with “±1σ Band”.
References: https://en.wikipedia.org/wiki/Throughput` + axesTip
	helpTTFB := `Average Time To First Byte (TTFB, in ms) for all requests in each batch (Overall/IPv4/IPv6).
- Captures latency before payload begins (DNS, TCP, TLS, server think time). Spikes often indicate setup or backend delays.
- Use TTFB Percentiles to see tail latency beyond the average (rare but impactful slow requests).
- Rolling overlays: optional Rolling Mean and a translucent μ±1σ band over a sliding window of N batches (N = Rolling Window control). Larger N = smoother mean; band width reflects variability. Toggle the band via “±1σ Band”.` + axesTip + "\nReferences: https://en.wikipedia.org/wiki/Time_to_first_byte"
	helpTTFBPct := `Percentiles of TTFB (ms): P50 (median), P90, P95, P99 per batch.
	- Expect P99 ≥ P95 ≥ P90 ≥ P50 by definition; bigger gaps mean heavier tail latency (spikes/outliers).
	- Investigate large P99 when the average looks fine; tail latency hurts user experience and systems throughput.
	References: https://en.wikipedia.org/wiki/Percentile , https://research.google/pubs/pub40801/` + axesTip
	helpSpeedPct := `Percentiles of throughput (per batch): P50 (median), P90, P95, P99 in the selected speed unit.
	- Shows distribution and variability of achieved speed beyond the average.
	- Use alongside Avg Speed to spot unstable networks (wide gaps between P50 and P95/P99).
	References: https://en.wikipedia.org/wiki/Percentile` + axesTip
	helpErr := `Error Rate per batch (Overall/IPv4/IPv6) as a percentage of lines with errors (TCP/HTTP failures).
- Sustained increases correlate with reliability issues or upstream/network faults.` + axesTip
	helpJitter := `Jitter (%): mean absolute relative variation between consecutive sampled speeds within a transfer.
- Higher jitter means more erratic throughput (bursts, stalls), often due to contention or queueing.` + axesTip + "\nReferences: https://en.wikipedia.org/wiki/Jitter"
	helpCoV := `Coefficient of Variation (%): standard deviation / mean of speeds.
- Another variability measure; higher values indicate less consistent throughput across samples.` + axesTip + "\nReferences: https://en.wikipedia.org/wiki/Coefficient_of_variation"
	helpCache := `Cache Hit Rate (%): fraction of requests likely served from intermediary caches (heuristics).
- High cache rates can hide origin latency; useful context when TTFB or speed looks unexpectedly good.` + axesTip + "\nReferences: https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching"
	helpProxy := `Proxy Suspected Rate (%): fraction of requests that appear to traverse enterprise/CDN proxies based on header/IP heuristics.
- Proxies can add overhead or improve cache locality; correlate with TTFB and speed changes.` + axesTip
	helpWarm := `Warm Cache Suspected Rate (%): fraction of requests likely benefiting from warm caches or connection reuse along the path.` + axesTip
	helpPlCount := `Plateau Count: average number of intra-transfer ‘stable’ speed segments detected per batch.
- Many plateaus can indicate buffering/flow control behavior or route/policy changes mid-transfer.` + axesTip + "\nReferences: https://en.wikipedia.org/wiki/TCP_congestion_control , https://en.wikipedia.org/wiki/Bufferbloat"
	helpPlLongest := `Longest Plateau (ms): duration of the longest stable segment in a transfer.
- Long plateaus at low speed can indicate stalls; long plateaus at high speed can indicate smooth steady-state.` + axesTip
	helpPlStable := `Plateau Stable Rate (%): fraction of time spent in stable plateaus during a transfer.
- Higher values often mean smoother throughput (less variability).` + axesTip

	// Stability & quality help
	helpLowSpeed := `Low-Speed Time Share (%): share of transfer time spent below the Low-Speed Threshold.
- Indicates how often the link is underperforming. Set the threshold in Settings → Low-Speed Threshold.
Computation: sample-based using intra-transfer speed samples and the selected threshold.` + axesTip
	helpStallRate := `Stall Rate (%): fraction of requests that experienced any stall during transfer.
- Useful for spotting reliability issues (buffering, retransmissions, outages).` + axesTip
	helpStallTime := `Avg Stall Time (ms): average total time spent stalled per request (across stalled requests).
- Correlate with Jitter/CoV to understand severity and duration of stalls.` + axesTip
	helpStallCount := `Stalled Requests Count: estimated number of stalled requests per batch.
- Interim metric derived as: round(Lines × Stall Rate / 100).
- Use alongside Stall Rate and Avg Stall Time.` + axesTip
	helpPartialBody := `Partial Body Rate (%): fraction of requests that finished with an incomplete body (Content-Length mismatch or early EOF).
- Helpful to spot flaky networks, proxies, or servers that terminate transfers prematurely.` + axesTip

	// Setup breakdown help
	helpDNS := `DNS Lookup Time (ms): average time to resolve the hostname.
 - Preferred source is httptrace (trace_dns_ms). When unavailable, legacy dns_time_ms is used.
 - Toggle Settings → "Overlay legacy DNS (dns_time_ms)" to overlay the legacy series (dashed) for comparison.
- Elevated values can indicate resolver or network issues.` + axesTip
	helpConn := `TCP Connect Time (ms): average time to establish the TCP connection (SYN→ACK and socket connect).
- Measured from httptrace connect start/done. Sensitive to RTT and packet loss.` + axesTip
	helpTLS := `TLS Handshake Time (ms): average time to complete TLS handshake.
- Includes ClientHello→ServerHello, cert exchange/verification. Spikes can indicate TLS inspection, cert revocation checks, or server load.` + axesTip

	// New charts help
	helpTail := `Tail Heaviness (Speed P99/P50): ratio of 99th to 50th percentile throughput per batch.
- Higher ratios mean a heavier tail and less predictable performance; ~1.0 is most stable.` + axesTip
	helpTTFBTail := `TTFB Tail Heaviness (P95/P50): ratio of 95th to 50th percentile TTFB per batch.
- Higher ratios indicate heavier tail latency; ~1.0 means tighter latency distribution.` + axesTip
	helpDeltas := `Family Delta (IPv6−IPv4): difference between IPv6 and IPv4.
- Speed Delta uses the chosen unit; positive means IPv6 faster.
- TTFB Delta is (IPv4−IPv6) in ms; positive means IPv6 lower (better) latency.` + axesTip
	helpSLA := `SLA Compliance (%): share of lines meeting thresholds.
	- Speed SLA: median (P50) speed ≥ threshold.
	- TTFB SLA: P95 TTFB ≤ threshold.
Set thresholds in Settings → SLA Thresholds (defaults: P50 ≥ 10,000 kbps; P95 TTFB ≤ 200 ms).` + axesTip

	// Extra comparisons
	helpDeltaPct := `Percent-based Family Deltas:
- Speed Δ%: (IPv6 − IPv4) / IPv4 × 100. Positive = IPv6 faster vs IPv4.
- TTFB Δ%: (IPv4 − IPv6) / IPv6 × 100. Positive = IPv6 lower (better) latency.` + axesTip
	helpSLADelta := `SLA Compliance Delta (pp): Difference in compliance (percentage points) between IPv6 and IPv4 using current thresholds.
- Speed SLA Δpp = IPv6 % − IPv4 % (using P50 speed threshold)
- TTFB SLA Δpp = IPv6 % − IPv4 % (using P95 TTFB threshold)` + axesTip

	// Tail/latency depth extra
	helpTTFBGap := `TTFB P95−P50 Gap (ms): difference between tail and median latency.
- Larger gaps indicate heavier latency tails (outliers/spikes).
- Use alongside Avg TTFB and TTFB Percentiles to spot tail issues hidden by averages.` + axesTip

	// Build separate grids for Speed and TTFB percentiles
	speedPctlGrid := container.NewVBox(
		container.NewStack(state.pctlOverallImg, state.pctlOverallOverlay),
		container.NewStack(state.pctlIPv4Img, state.pctlIPv4Overlay),
		container.NewStack(state.pctlIPv6Img, state.pctlIPv6Overlay),
	)
	ttfbPctlGrid := container.NewVBox(
		container.NewStack(state.tpctlOverallImg, state.tpctlOverallOverlay),
		container.NewStack(state.tpctlIPv4Img, state.tpctlIPv4Overlay),
		container.NewStack(state.tpctlIPv6Img, state.tpctlIPv6Overlay),
	)

	// charts column (hints are rendered inside chart images when enabled)
	// Requested order: DNS, TCP Connect, TLS Handshake at the top, then the rest.
	helpPreTTFB := `Pre‑TTFB Stall Rate (%): fraction of requests canceled due to a pre‑TTFB stall (no first byte within stall timeout).\n- Requires monitor runs with --pre-ttfb-stall.\n- Useful to spot early server/network stalls before any response bytes.` + axesTip
	// Build Pre‑TTFB section block separately so we can hide/show it dynamically
	state.pretffbSection = makeChartSection(state, "Pre‑TTFB Stall Rate", helpPreTTFB, container.NewStack(state.pretffbImgCanvas, state.pretffbOverlay))
	state.pretffbBlock = container.NewVBox(widget.NewSeparator(), state.pretffbSection)

	chartsColumn := container.NewVBox(
		makeChartSection(state, "DNS Lookup Time (ms)", helpDNS, container.NewStack(state.setupDNSImgCanvas, state.setupDNSOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "TCP Connect Time (ms)", helpConn, container.NewStack(state.setupConnImgCanvas, state.setupConnOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "TLS Handshake Time (ms)", helpTLS, container.NewStack(state.setupTLSImgCanvas, state.setupTLSOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "HTTP Protocol Mix (%)", "Share of requests by HTTP protocol (e.g., HTTP/2 vs HTTP/1.1)."+axesTip, container.NewStack(state.protocolMixImgCanvas, state.protocolMixOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Avg Speed by HTTP Protocol", "Average speed per HTTP protocol. Helps compare protocol performance."+axesTip, container.NewStack(state.protocolAvgSpeedImgCanvas, state.protocolAvgSpeedOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Stall Rate by HTTP Protocol (%)", "Stall rate per protocol. Higher means more stalls."+axesTip, container.NewStack(state.protocolStallRateImgCanvas, state.protocolStallRateOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Partial Body Rate by HTTP Protocol (%)", "Percentage of requests with incomplete body per protocol. Helps spot protocol-specific truncations or early EOF."+axesTip, container.NewStack(state.protocolPartialRateImgCanvas, state.protocolPartialRateOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Error Rate by HTTP Protocol (%)", "Per‑protocol error prevalence: for each HTTP protocol, the fraction of that protocol’s requests that errored.\n\nNote: These values do not add up to 100% because each bar is normalized by its own protocol’s volume, not the total errors across all protocols. Missing percentage is therefore expected. (Unknown protocol is counted as ‘(unknown)’ if present)."+axesTip, container.NewStack(state.protocolErrorRateImgCanvas, state.protocolErrorRateOverlay)),
		makeChartSection(state, "Error Share by HTTP Protocol (%)", "Share of total errors attributed to each HTTP protocol. Bars typically sum to about 100% (across protocols with errors). This complements ‘Error Rate by HTTP Protocol’, which normalizes by each protocol’s request volume and therefore does not sum to 100%."+axesTip, container.NewStack(state.protocolErrorShareImgCanvas, state.protocolErrorShareOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "TLS Version Mix (%)", "Share of requests by negotiated TLS version."+axesTip, container.NewStack(state.tlsVersionMixImgCanvas, state.tlsVersionMixOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "ALPN Mix (%)", "Share of requests by negotiated ALPN (e.g., h2, http/1.1)."+axesTip, container.NewStack(state.alpnMixImgCanvas, state.alpnMixOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Chunked Transfer Rate (%)", "Percentage of responses using chunked transfer encoding."+axesTip, container.NewStack(state.chunkedRateImgCanvas, state.chunkedRateOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Speed", helpSpeed, container.NewStack(state.speedImgCanvas, state.speedOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Local Throughput Self-Test", "Local loopback throughput measured on startup. Useful as a device + OS baseline to compare against network speeds."+axesTip, container.NewStack(state.selfTestImgCanvas, state.selfTestOverlay)),
		widget.NewSeparator(),
		// Place Speed Percentiles directly under Avg Speed
		makeChartSection(state, "Speed Percentiles", helpSpeedPct, speedPctlGrid),
		widget.NewSeparator(),
		makeChartSection(state, "TTFB (Avg)", helpTTFB, container.NewStack(state.ttfbImgCanvas, state.ttfbOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "TTFB Percentiles", helpTTFBPct, ttfbPctlGrid),
		widget.NewSeparator(),
		makeChartSection(state, "Tail Heaviness (P99/P50 Speed)", helpTail, container.NewStack(state.tailRatioImgCanvas, state.tailRatioOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "TTFB Tail Heaviness (P95/P50)", helpTTFBTail, container.NewStack(state.ttfbTailRatioImgCanvas, state.ttfbTailRatioOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Family Delta – Speed (IPv6−IPv4)", helpDeltas, container.NewStack(state.speedDeltaImgCanvas, state.speedDeltaOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Family Delta – TTFB (IPv4−IPv6)", helpDeltas, container.NewStack(state.ttfbDeltaImgCanvas, state.ttfbDeltaOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Family Delta – Speed % (IPv6 vs IPv4)", helpDeltaPct, container.NewStack(state.speedDeltaPctImgCanvas, state.speedDeltaPctOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Family Delta – TTFB % (IPv6 vs IPv4)", helpDeltaPct, container.NewStack(state.ttfbDeltaPctImgCanvas, state.ttfbDeltaPctOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "SLA Compliance – Speed", helpSLA, container.NewStack(state.slaSpeedImgCanvas, state.slaSpeedOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "SLA Compliance – TTFB", helpSLA, container.NewStack(state.slaTTFBImgCanvas, state.slaTTFBOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "SLA Compliance Delta – Speed (pp)", helpSLADelta, container.NewStack(state.slaSpeedDeltaImgCanvas, state.slaSpeedDeltaOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "SLA Compliance Delta – TTFB (pp)", helpSLADelta, container.NewStack(state.slaTTFBDeltaImgCanvas, state.slaTTFBDeltaOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "TTFB P95−P50 Gap", helpTTFBGap, container.NewStack(state.tpctlP95GapImgCanvas, state.tpctlP95GapOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Error Rate", helpErr, container.NewStack(state.errImgCanvas, state.errOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Jitter", helpJitter, container.NewStack(state.jitterImgCanvas, state.jitterOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Coefficient of Variation", helpCoV, container.NewStack(state.covImgCanvas, state.covOverlay)),
		widget.NewSeparator(),
		// Stability & quality section
		makeChartSection(state, "Low-Speed Time Share", helpLowSpeed, container.NewStack(state.lowSpeedImgCanvas, state.lowSpeedOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Stall Rate", helpStallRate, container.NewStack(state.stallRateImgCanvas, state.stallRateOverlay)),
		// Pre‑TTFB block (may be hidden when metric is all‑zero across all batches)
		state.pretffbBlock,
		widget.NewSeparator(),
		makeChartSection(state, "Partial Body Rate", helpPartialBody, container.NewStack(state.partialBodyImgCanvas, state.partialBodyOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Stalled Requests Count", helpStallCount, container.NewStack(state.stallCountImgCanvas, state.stallCountOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Avg Stall Time", helpStallTime, container.NewStack(state.stallTimeImgCanvas, state.stallTimeOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Cache Hit Rate", helpCache, container.NewStack(state.cacheImgCanvas, state.cacheOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Proxy Suspected Rate", helpProxy, container.NewStack(state.proxyImgCanvas, state.proxyOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Warm Cache Suspected Rate", helpWarm, container.NewStack(state.warmCacheImgCanvas, state.warmCacheOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Plateau Count", helpPlCount, container.NewStack(state.plCountImgCanvas, state.plCountOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Longest Plateau", helpPlLongest, container.NewStack(state.plLongestImgCanvas, state.plLongestOverlay)),
		widget.NewSeparator(),
		makeChartSection(state, "Plateau Stable Rate", helpPlStable, container.NewStack(state.plStableImgCanvas, state.plStableOverlay)),
	)
	// Always show stacked percentiles
	speedPctlGrid.Show()
	ttfbPctlGrid.Show()
	chartsScroll := container.NewVScroll(chartsColumn)
	// Remove wide minimums to allow shrinking the window freely
	chartsScroll.SetMinSize(fyne.NewSize(0, 0))
	state.chartsScroll = chartsScroll
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
	// Use the horizontally scrollable toolbar at the top
	content := container.NewBorder(topScroll, nil, nil, nil, tabs)
	w.SetContent(content)
	// Initialize find matches now that chartRefs are registered
	updateFindMatches(state)

	// Redraw charts on window resize so they scale with width
	if w.Canvas() != nil {
		prevW := int(w.Canvas().Size().Width)
		// Minimum pixel delta to consider as a real resize. Avoids redraw loops from tiny width jitters.
		const minWidthDelta = 8
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
						if curW > prevW+minWidthDelta || curW < prevW-minWidthDelta {
							prevW = curW
							fyne.Do(func() {
								redrawCharts(state)
							})
						}
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

	// (X-Axis and Y-Scale callbacks moved to Settings menu)
	// (removed: pctlFamily/change and compare handlers)
	ipv4Chk.OnChanged = func(b bool) { state.showIPv4 = b; savePrefs(state); updateColumnVisibility(state); redrawCharts(state) }
	ipv6Chk.OnChanged = func(b bool) { state.showIPv6 = b; savePrefs(state); updateColumnVisibility(state); redrawCharts(state) }
	// (crosshair toggle moved to Settings menu)

	// (removed duplicate wiring block)

	// menus, prefs, initial load
	buildMenus(state, fileLabel)
	loadPrefs(state, overallChk, ipv4Chk, ipv6Chk, fileLabel, tabs)
	// Pre-populate Situation selector to reflect saved preference immediately (no save on init)
	if state.situationSelect != nil {
		if strings.TrimSpace(state.situation) == "" || strings.EqualFold(state.situation, "All") {
			state.situation = "All"
			state.situationSelect.Options = []string{"All"}
			state.initializing = true
			state.situationSelect.SetSelected("All")
			state.initializing = false
			state.situationSelect.PlaceHolder = "All"
		} else {
			state.situationSelect.Options = []string{"All", state.situation}
			state.initializing = true
			state.situationSelect.SetSelected(state.situation)
			state.initializing = false
			state.situationSelect.PlaceHolder = state.situation
		}
		state.situationSelect.Refresh()
	}
	// (SLA and low-speed inputs removed from toolbar)
	// Set initial checkbox states explicitly now that callbacks exist
	overallChk.SetChecked(state.showOverall)
	ipv4Chk.SetChecked(state.showIPv4)
	ipv6Chk.SetChecked(state.showIPv6)
	// (DNS legacy checkbox removed from toolbar)
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
	if state.setupDNSOverlay != nil {
		state.setupDNSOverlay.enabled = state.crosshairEnabled
		state.setupDNSOverlay.Refresh()
	}
	if state.setupConnOverlay != nil {
		state.setupConnOverlay.enabled = state.crosshairEnabled
		state.setupConnOverlay.Refresh()
	}
	if state.setupTLSOverlay != nil {
		state.setupTLSOverlay.enabled = state.crosshairEnabled
		state.setupTLSOverlay.Refresh()
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
	if state.protocolMixOverlay != nil {
		state.protocolMixOverlay.enabled = state.crosshairEnabled
		state.protocolMixOverlay.Refresh()
	}
	if state.protocolAvgSpeedOverlay != nil {
		state.protocolAvgSpeedOverlay.enabled = state.crosshairEnabled
		state.protocolAvgSpeedOverlay.Refresh()
	}
	if state.protocolStallRateOverlay != nil {
		state.protocolStallRateOverlay.enabled = state.crosshairEnabled
		state.protocolStallRateOverlay.Refresh()
	}
	if state.protocolErrorRateOverlay != nil {
		state.protocolErrorRateOverlay.enabled = state.crosshairEnabled
		state.protocolErrorRateOverlay.Refresh()
	}
	if state.protocolErrorShareOverlay != nil {
		state.protocolErrorShareOverlay.enabled = state.crosshairEnabled
		state.protocolErrorShareOverlay.Refresh()
	}
	if state.protocolErrorShareOverlay != nil {
		state.protocolErrorShareOverlay.enabled = state.crosshairEnabled
		state.protocolErrorShareOverlay.Refresh()
	}
	if state.tlsVersionMixOverlay != nil {
		state.tlsVersionMixOverlay.enabled = state.crosshairEnabled
		state.tlsVersionMixOverlay.Refresh()
	}
	if state.alpnMixOverlay != nil {
		state.alpnMixOverlay.enabled = state.crosshairEnabled
		state.alpnMixOverlay.Refresh()
	}
	if state.chunkedRateOverlay != nil {
		state.chunkedRateOverlay.enabled = state.crosshairEnabled
		state.chunkedRateOverlay.Refresh()
	}
	if state.tailRatioOverlay != nil {
		state.tailRatioOverlay.enabled = state.crosshairEnabled
		state.tailRatioOverlay.Refresh()
	}
	if state.ttfbTailRatioOverlay != nil {
		state.ttfbTailRatioOverlay.enabled = state.crosshairEnabled
		state.ttfbTailRatioOverlay.Refresh()
	}
	if state.speedDeltaPctOverlay != nil {
		state.speedDeltaPctOverlay.enabled = state.crosshairEnabled
		state.speedDeltaPctOverlay.Refresh()
	}
	if state.ttfbDeltaPctOverlay != nil {
		state.ttfbDeltaPctOverlay.enabled = state.crosshairEnabled
		state.ttfbDeltaPctOverlay.Refresh()
	}
	if state.slaSpeedDeltaOverlay != nil {
		state.slaSpeedDeltaOverlay.enabled = state.crosshairEnabled
		state.slaSpeedDeltaOverlay.Refresh()
	}
	if state.slaTTFBDeltaOverlay != nil {
		state.slaTTFBDeltaOverlay.enabled = state.crosshairEnabled
		state.slaTTFBDeltaOverlay.Refresh()
	}
	if state.speedDeltaOverlay != nil {
		state.speedDeltaOverlay.enabled = state.crosshairEnabled
		state.speedDeltaOverlay.Refresh()
	}
	if state.ttfbDeltaOverlay != nil {
		state.ttfbDeltaOverlay.enabled = state.crosshairEnabled
		state.ttfbDeltaOverlay.Refresh()
	}
	if state.slaSpeedOverlay != nil {
		state.slaSpeedOverlay.enabled = state.crosshairEnabled
		state.slaSpeedOverlay.Refresh()
	}
	if state.slaTTFBOverlay != nil {
		state.slaTTFBOverlay.enabled = state.crosshairEnabled
		state.slaTTFBOverlay.Refresh()
	}
	if state.lowSpeedOverlay != nil {
		state.lowSpeedOverlay.enabled = state.crosshairEnabled
		state.lowSpeedOverlay.Refresh()
	}
	if state.stallRateOverlay != nil {
		state.stallRateOverlay.enabled = state.crosshairEnabled
		state.stallRateOverlay.Refresh()
	}
	if state.stallTimeOverlay != nil {
		state.stallTimeOverlay.enabled = state.crosshairEnabled
		state.stallTimeOverlay.Refresh()
	}
	if state.stallCountOverlay != nil {
		state.stallCountOverlay.enabled = state.crosshairEnabled
		state.stallCountOverlay.Refresh()
	}
	if state.partialBodyOverlay != nil {
		state.partialBodyOverlay.enabled = state.crosshairEnabled
		state.partialBodyOverlay.Refresh()
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
	exportPctlOverall := fyne.NewMenuItem("Export Speed Percentiles – Overall…", func() { exportChartPNG(state, state.pctlOverallImg, "percentiles_overall.png") })
	exportPctlIPv4 := fyne.NewMenuItem("Export Speed Percentiles – IPv4…", func() { exportChartPNG(state, state.pctlIPv4Img, "percentiles_ipv4.png") })
	exportPctlIPv6 := fyne.NewMenuItem("Export Speed Percentiles – IPv6…", func() { exportChartPNG(state, state.pctlIPv6Img, "percentiles_ipv6.png") })
	// TTFB percentiles exports
	exportTPctlOverall := fyne.NewMenuItem("Export TTFB Percentiles – Overall…", func() { exportChartPNG(state, state.tpctlOverallImg, "ttfb_percentiles_overall.png") })
	exportTPctlIPv4 := fyne.NewMenuItem("Export TTFB Percentiles – IPv4…", func() { exportChartPNG(state, state.tpctlIPv4Img, "ttfb_percentiles_ipv4.png") })
	exportTPctlIPv6 := fyne.NewMenuItem("Export TTFB Percentiles – IPv6…", func() { exportChartPNG(state, state.tpctlIPv6Img, "ttfb_percentiles_ipv6.png") })
	// New diagnostic charts exports
	exportTailRatio := fyne.NewMenuItem("Export Tail Heaviness Chart…", func() { exportChartPNG(state, state.tailRatioImgCanvas, "tail_heaviness_chart.png") })
	exportTTFBTailRatio := fyne.NewMenuItem("Export TTFB Tail Heaviness (P95/P50)…", func() { exportChartPNG(state, state.ttfbTailRatioImgCanvas, "ttfb_tail_heaviness_chart.png") })
	exportSpeedDelta := fyne.NewMenuItem("Export Family Delta – Speed…", func() { exportChartPNG(state, state.speedDeltaImgCanvas, "family_delta_speed_chart.png") })
	exportTTFBDelta := fyne.NewMenuItem("Export Family Delta – TTFB…", func() { exportChartPNG(state, state.ttfbDeltaImgCanvas, "family_delta_ttfb_chart.png") })
	exportSpeedDeltaPct := fyne.NewMenuItem("Export Family Delta – Speed %…", func() { exportChartPNG(state, state.speedDeltaPctImgCanvas, "family_delta_speed_pct_chart.png") })
	exportTTFBDeltaPct := fyne.NewMenuItem("Export Family Delta – TTFB %…", func() { exportChartPNG(state, state.ttfbDeltaPctImgCanvas, "family_delta_ttfb_pct_chart.png") })
	exportSLASpeed := fyne.NewMenuItem("Export SLA Compliance – Speed…", func() { exportChartPNG(state, state.slaSpeedImgCanvas, "sla_compliance_speed_chart.png") })
	exportSLATTFB := fyne.NewMenuItem("Export SLA Compliance – TTFB…", func() { exportChartPNG(state, state.slaTTFBImgCanvas, "sla_compliance_ttfb_chart.png") })
	exportSLASpeedDelta := fyne.NewMenuItem("Export SLA Compliance Delta – Speed (pp)…", func() { exportChartPNG(state, state.slaSpeedDeltaImgCanvas, "sla_compliance_delta_speed_chart.png") })
	exportSLATTFBDelta := fyne.NewMenuItem("Export SLA Compliance Delta – TTFB (pp)…", func() { exportChartPNG(state, state.slaTTFBDeltaImgCanvas, "sla_compliance_delta_ttfb_chart.png") })
	exportTTFBGap := fyne.NewMenuItem("Export TTFB P95−P50 Gap…", func() { exportChartPNG(state, state.tpctlP95GapImgCanvas, "ttfb_p95_p50_gap_chart.png") })
	exportErrors := fyne.NewMenuItem("Export Error Rate Chart…", func() { exportChartPNG(state, state.errImgCanvas, "error_rate_chart.png") })
	exportJitter := fyne.NewMenuItem("Export Jitter Chart…", func() { exportChartPNG(state, state.jitterImgCanvas, "jitter_chart.png") })
	exportCoV := fyne.NewMenuItem("Export CoV Chart…", func() { exportChartPNG(state, state.covImgCanvas, "cov_chart.png") })
	// Self-test export
	exportSelfTest := fyne.NewMenuItem("Export Local Throughput Self-Test…", func() { exportChartPNG(state, state.selfTestImgCanvas, "local_throughput_selftest_chart.png") })
	// Connection setup breakdown exports
	exportDNS := fyne.NewMenuItem("Export DNS Lookup Time Chart…", func() { exportChartPNG(state, state.setupDNSImgCanvas, "dns_lookup_time_chart.png") })
	exportConn := fyne.NewMenuItem("Export TCP Connect Time Chart…", func() { exportChartPNG(state, state.setupConnImgCanvas, "tcp_connect_time_chart.png") })
	exportTLS := fyne.NewMenuItem("Export TLS Handshake Time Chart…", func() { exportChartPNG(state, state.setupTLSImgCanvas, "tls_handshake_time_chart.png") })
	// Transport/Protocol exports
	exportProtocolMix := fyne.NewMenuItem("Export HTTP Protocol Mix…", func() { exportChartPNG(state, state.protocolMixImgCanvas, "http_protocol_mix_chart.png") })
	exportProtocolAvgSpeed := fyne.NewMenuItem("Export Avg Speed by HTTP Protocol…", func() { exportChartPNG(state, state.protocolAvgSpeedImgCanvas, "avg_speed_by_http_protocol_chart.png") })
	exportProtocolStallRate := fyne.NewMenuItem("Export Stall Rate by HTTP Protocol…", func() {
		exportChartPNG(state, state.protocolStallRateImgCanvas, "stall_rate_by_http_protocol_chart.png")
	})
	exportProtocolErrorRate := fyne.NewMenuItem("Export Error Rate by HTTP Protocol…", func() {
		exportChartPNG(state, state.protocolErrorRateImgCanvas, "error_rate_by_http_protocol_chart.png")
	})
	exportProtocolErrorShare := fyne.NewMenuItem("Export Error Share by HTTP Protocol…", func() {
		exportChartPNG(state, state.protocolErrorShareImgCanvas, "error_share_by_http_protocol_chart.png")
	})
	exportProtocolPartialRate := fyne.NewMenuItem("Export Partial Body Rate by HTTP Protocol…", func() {
		exportChartPNG(state, state.protocolPartialRateImgCanvas, "partial_body_rate_by_http_protocol_chart.png")
	})
	exportTLSMix := fyne.NewMenuItem("Export TLS Version Mix…", func() { exportChartPNG(state, state.tlsVersionMixImgCanvas, "tls_version_mix_chart.png") })
	exportALPNMix := fyne.NewMenuItem("Export ALPN Mix…", func() { exportChartPNG(state, state.alpnMixImgCanvas, "alpn_mix_chart.png") })
	exportChunkedRate := fyne.NewMenuItem("Export Chunked Transfer Rate…", func() { exportChartPNG(state, state.chunkedRateImgCanvas, "chunked_transfer_rate_chart.png") })
	// Setup Timings submenu (exports only; DNS legacy overlay toggle moved to Settings)
	setupSub := fyne.NewMenu("Setup Timings",
		exportDNS,
		exportConn,
		exportTLS,
	)
	setupSubItem := fyne.NewMenuItem("Setup Timings", nil)
	setupSubItem.ChildMenu = setupSub
	// Transport/Protocol submenu
	transportSub := fyne.NewMenu("Transport",
		exportProtocolMix,
		exportProtocolAvgSpeed,
		exportProtocolStallRate,
		exportProtocolPartialRate,
		exportProtocolErrorRate,
		exportProtocolErrorShare,
		fyne.NewMenuItemSeparator(),
		exportTLSMix,
		exportALPNMix,
		exportChunkedRate,
	)
	transportSubItem := fyne.NewMenuItem("Transport", nil)
	transportSubItem.ChildMenu = transportSub
	// Stability exports
	exportLowSpeed := fyne.NewMenuItem("Export Low-Speed Time Share Chart…", func() { exportChartPNG(state, state.lowSpeedImgCanvas, "low_speed_time_share_chart.png") })
	exportStallRate := fyne.NewMenuItem("Export Stall Rate Chart…", func() { exportChartPNG(state, state.stallRateImgCanvas, "stall_rate_chart.png") })
	exportPreTTFB := fyne.NewMenuItem("Export Pre‑TTFB Stall Rate Chart…", func() { exportChartPNG(state, state.pretffbImgCanvas, "pretffb_stall_rate_chart.png") })
	exportStallTime := fyne.NewMenuItem("Export Avg Stall Time Chart…", func() { exportChartPNG(state, state.stallTimeImgCanvas, "avg_stall_time_chart.png") })
	// Interim stability export
	exportStallCount := fyne.NewMenuItem("Export Stalled Requests Count…", func() { exportChartPNG(state, state.stallCountImgCanvas, "stall_count_chart.png") })
	exportPartialBody := fyne.NewMenuItem("Export Partial Body Rate Chart…", func() { exportChartPNG(state, state.partialBodyImgCanvas, "partial_body_rate_chart.png") })
	exportCache := fyne.NewMenuItem("Export Cache Hit Rate Chart…", func() { exportChartPNG(state, state.cacheImgCanvas, "cache_hit_rate_chart.png") })
	exportProxy := fyne.NewMenuItem("Export Proxy Suspected Rate Chart…", func() { exportChartPNG(state, state.proxyImgCanvas, "proxy_suspected_rate_chart.png") })
	exportWarmCache := fyne.NewMenuItem("Export Warm Cache Suspected Rate Chart…", func() { exportChartPNG(state, state.warmCacheImgCanvas, "warm_cache_suspected_rate_chart.png") })
	exportPlCount := fyne.NewMenuItem("Export Plateau Count Chart…", func() { exportChartPNG(state, state.plCountImgCanvas, "plateau_count_chart.png") })
	exportPlLongest := fyne.NewMenuItem("Export Longest Plateau Chart…", func() { exportChartPNG(state, state.plLongestImgCanvas, "plateau_longest_chart.png") })
	exportPlStable := fyne.NewMenuItem("Export Plateau Stable Rate Chart…", func() { exportChartPNG(state, state.plStableImgCanvas, "plateau_stable_rate_chart.png") })
	exportAll := fyne.NewMenuItem("Export All Charts (One Image)…", func() { exportAllChartsCombined(state) })
	// Create logical submenus to reduce clutter
	avgSub := fyne.NewMenu("Averages & Percentiles",
		exportSpeed,
		exportPctlOverall,
		exportPctlIPv4,
		exportPctlIPv6,
		fyne.NewMenuItemSeparator(),
		exportTTFB,
		exportTPctlOverall,
		exportTPctlIPv4,
		exportTPctlIPv6,
	)
	avgSubItem := fyne.NewMenuItem("Averages & Percentiles", nil)
	avgSubItem.ChildMenu = avgSub

	diagSub := fyne.NewMenu("Diagnostics",
		exportTailRatio,
		exportTTFBTailRatio,
		exportTTFBGap,
		exportSelfTest,
	)
	diagSubItem := fyne.NewMenuItem("Diagnostics", nil)
	diagSubItem.ChildMenu = diagSub

	deltasSub := fyne.NewMenu("Family Deltas",
		exportSpeedDelta,
		exportTTFBDelta,
		exportSpeedDeltaPct,
		exportTTFBDeltaPct,
	)
	deltasSubItem := fyne.NewMenuItem("Family Deltas", nil)
	deltasSubItem.ChildMenu = deltasSub

	slaSub := fyne.NewMenu("SLA",
		exportSLASpeed,
		exportSLATTFB,
		exportSLASpeedDelta,
		exportSLATTFBDelta,
	)
	slaSubItem := fyne.NewMenuItem("SLA", nil)
	slaSubItem.ChildMenu = slaSub

	errorsSub := fyne.NewMenu("Errors & Variability",
		exportErrors,
		exportJitter,
		exportCoV,
	)
	errorsSubItem := fyne.NewMenuItem("Errors & Variability", nil)
	errorsSubItem.ChildMenu = errorsSub

	stabilitySub := fyne.NewMenu("Stability & Quality",
		exportLowSpeed,
		exportStallRate,
		exportPreTTFB,
		exportPartialBody,
		exportStallCount,
		exportStallTime,
	)
	stabilitySubItem := fyne.NewMenuItem("Stability & Quality", nil)
	stabilitySubItem.ChildMenu = stabilitySub

	cacheSub := fyne.NewMenu("Cache & Proxy",
		exportCache,
		exportProxy,
		exportWarmCache,
	)
	cacheSubItem := fyne.NewMenuItem("Cache & Proxy", nil)
	cacheSubItem.ChildMenu = cacheSub

	platSub := fyne.NewMenu("Plateaus",
		exportPlCount,
		exportPlLongest,
		exportPlStable,
	)
	platSubItem := fyne.NewMenuItem("Plateaus", nil)
	platSubItem.ChildMenu = platSub

	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Open…", func() { openFileDialog(state, fileLabel) }),
		fyne.NewMenuItem("Reload", func() { loadAll(state, fileLabel) }),
		fyne.NewMenuItemSeparator(),
		setupSubItem,
		transportSubItem,
		avgSubItem,
		diagSubItem,
		deltasSubItem,
		slaSubItem,
		errorsSubItem,
		stabilitySubItem,
		cacheSubItem,
		platSubItem,
		fyne.NewMenuItemSeparator(),
		exportAll,
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() { state.window.Close() }),
	)
	// Settings menu: includes Screenshot Theme (Auto/Dark/Light) and other toggles
	themeLabelFor := func(name string) string {
		// name is one of Auto/Dark/Light
		switch name {
		case "Auto":
			if strings.EqualFold(screenshotThemeMode, "auto") {
				return name + " ✓"
			}
		case "Dark":
			if strings.EqualFold(screenshotThemeMode, "dark") {
				return name + " ✓"
			}
		case "Light":
			if strings.EqualFold(screenshotThemeMode, "light") {
				return name + " ✓"
			}
		}
		return name
	}
	autoItem := fyne.NewMenuItem(themeLabelFor("Auto"), func() {
		if strings.EqualFold(screenshotThemeMode, "auto") {
			return
		}
		screenshotThemeMode = "auto"
		state.app.Preferences().SetString("screenshotThemeMode", screenshotThemeMode)
		// Resolve current effective theme and apply
		screenshotThemeGlobal = resolveTheme(screenshotThemeMode, state.app)
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { redrawCharts(state) })
		}()
		go func() {
			time.Sleep(50 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})
	darkItem := fyne.NewMenuItem(themeLabelFor("Dark"), func() {
		if strings.EqualFold(screenshotThemeMode, "dark") {
			return
		}
		screenshotThemeMode = "dark"
		state.app.Preferences().SetString("screenshotThemeMode", screenshotThemeMode)
		screenshotThemeGlobal = resolveTheme(screenshotThemeMode, state.app)
		// Redraw charts to reflect watermark/hint/background contrast if applicable
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { redrawCharts(state) })
		}()
		// Rebuild menus asynchronously to avoid changing menus while handling them
		go func() {
			time.Sleep(50 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})
	lightItem := fyne.NewMenuItem(themeLabelFor("Light"), func() {
		if strings.EqualFold(screenshotThemeMode, "light") {
			return
		}
		screenshotThemeMode = "light"
		state.app.Preferences().SetString("screenshotThemeMode", screenshotThemeMode)
		screenshotThemeGlobal = resolveTheme(screenshotThemeMode, state.app)
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { redrawCharts(state) })
		}()
		go func() {
			time.Sleep(50 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})
	// Crosshair toggle menu item
	crosshairLabel := func() string {
		if state.crosshairEnabled {
			return "Crosshair ✓"
		}
		return "Crosshair"
	}
	crosshairToggle := fyne.NewMenuItem(crosshairLabel(), func() {
		b := !state.crosshairEnabled
		state.crosshairEnabled = b
		savePrefs(state)
		// Apply to all overlays
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
		if state.protocolMixOverlay != nil {
			state.protocolMixOverlay.enabled = b
			state.protocolMixOverlay.Refresh()
		}
		if state.protocolAvgSpeedOverlay != nil {
			state.protocolAvgSpeedOverlay.enabled = b
			state.protocolAvgSpeedOverlay.Refresh()
		}
		if state.protocolStallRateOverlay != nil {
			state.protocolStallRateOverlay.enabled = b
			state.protocolStallRateOverlay.Refresh()
		}
		if state.protocolErrorRateOverlay != nil {
			state.protocolErrorRateOverlay.enabled = b
			state.protocolErrorRateOverlay.Refresh()
		}
		if state.protocolPartialRateOverlay != nil {
			state.protocolPartialRateOverlay.enabled = b
			state.protocolPartialRateOverlay.Refresh()
		}
		if state.tlsVersionMixOverlay != nil {
			state.tlsVersionMixOverlay.enabled = b
			state.tlsVersionMixOverlay.Refresh()
		}
		if state.alpnMixOverlay != nil {
			state.alpnMixOverlay.enabled = b
			state.alpnMixOverlay.Refresh()
		}
		if state.chunkedRateOverlay != nil {
			state.chunkedRateOverlay.enabled = b
			state.chunkedRateOverlay.Refresh()
		}
		if state.setupDNSOverlay != nil {
			state.setupDNSOverlay.enabled = b
			state.setupDNSOverlay.Refresh()
		}
		if state.setupConnOverlay != nil {
			state.setupConnOverlay.enabled = b
			state.setupConnOverlay.Refresh()
		}
		if state.setupTLSOverlay != nil {
			state.setupTLSOverlay.enabled = b
			state.setupTLSOverlay.Refresh()
		}
		if state.tailRatioOverlay != nil {
			state.tailRatioOverlay.enabled = b
			state.tailRatioOverlay.Refresh()
		}
		if state.speedDeltaOverlay != nil {
			state.speedDeltaOverlay.enabled = b
			state.speedDeltaOverlay.Refresh()
		}
		if state.ttfbDeltaOverlay != nil {
			state.ttfbDeltaOverlay.enabled = b
			state.ttfbDeltaOverlay.Refresh()
		}
		if state.slaSpeedOverlay != nil {
			state.slaSpeedOverlay.enabled = b
			state.slaSpeedOverlay.Refresh()
		}
		if state.slaTTFBOverlay != nil {
			state.slaTTFBOverlay.enabled = b
			state.slaTTFBOverlay.Refresh()
		}
		if state.lowSpeedOverlay != nil {
			state.lowSpeedOverlay.enabled = b
			state.lowSpeedOverlay.Refresh()
		}
		if state.stallRateOverlay != nil {
			state.stallRateOverlay.enabled = b
			state.stallRateOverlay.Refresh()
		}
		if state.stallTimeOverlay != nil {
			state.stallTimeOverlay.enabled = b
			state.stallTimeOverlay.Refresh()
		}
		if state.stallCountOverlay != nil {
			state.stallCountOverlay.enabled = b
			state.stallCountOverlay.Refresh()
		}
		// refresh menu label
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})
	// Pre‑TTFB chart toggle
	pretffbLabel := func() string {
		if state.showPreTTFB {
			return "Pre‑TTFB Chart ✓"
		}
		return "Pre‑TTFB Chart"
	}
	pretffbToggle := fyne.NewMenuItem(pretffbLabel(), func() {
		state.showPreTTFB = !state.showPreTTFB
		savePrefs(state)
		// Apply immediately
		if state.pretffbBlock != nil {
			if state.showPreTTFB {
				state.pretffbBlock.Show()
			} else {
				state.pretffbBlock.Hide()
			}
			state.pretffbBlock.Refresh()
		}
		// Rebuild menus to update checkmark
		go func() {
			time.Sleep(40 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})
	// Pre‑TTFB auto-hide toggle (only hide when metric is all zero)
	autoHidePretffbLabel := func() string {
		if state.autoHidePreTTFB {
			return "Auto‑hide Pre‑TTFB (zero) ✓"
		}
		return "Auto‑hide Pre‑TTFB (zero)"
	}
	autoHidePretffbToggle := fyne.NewMenuItem(autoHidePretffbLabel(), func() {
		state.autoHidePreTTFB = !state.autoHidePreTTFB
		savePrefs(state)
		// Re-render to apply visibility based on current data
		redrawCharts(state)
		// Update menu label
		go func() {
			time.Sleep(40 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})

	// Hints toggle
	hintsLabel := func() string {
		if state.showHints {
			return "Hints ✓"
		}
		return "Hints"
	}
	hintsToggle := fyne.NewMenuItem(hintsLabel(), func() {
		state.showHints = !state.showHints
		savePrefs(state)
		redrawCharts(state)
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})

	// Rolling overlays toggles
	rollingLabel := func() string {
		if state.showRolling {
			return "Rolling Overlays ✓"
		}
		return "Rolling Overlays"
	}
	rollingToggle := fyne.NewMenuItem(rollingLabel(), func() {
		state.showRolling = !state.showRolling
		savePrefs(state)
		redrawCharts(state)
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})
	bandLabel := func() string {
		if state.showRollingBand {
			return "±1σ Band ✓"
		}
		return "±1σ Band"
	}
	bandToggle := fyne.NewMenuItem(bandLabel(), func() {
		state.showRollingBand = !state.showRollingBand
		savePrefs(state)
		redrawCharts(state)
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})

	// DNS legacy overlay toggle moved here
	dnsLabel := func() string {
		if state.showDNSLegacy {
			return "Overlay legacy DNS (dns_time_ms) ✓"
		}
		return "Overlay legacy DNS (dns_time_ms)"
	}
	dnsToggle := fyne.NewMenuItem(dnsLabel(), func() {
		state.showDNSLegacy = !state.showDNSLegacy
		savePrefs(state)
		redrawCharts(state)
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	})

	// Theme submenu under Settings
	themeSub := fyne.NewMenu("Screenshot Theme", autoItem, darkItem, lightItem)
	themeSubItem := fyne.NewMenuItem("Screenshot Theme", nil)
	themeSubItem.ChildMenu = themeSub

	// Speed Unit submenu under Settings
	speedUnitLabelFor := func(u string) string {
		if strings.EqualFold(state.speedUnit, u) {
			return u + " ✓"
		}
		return u
	}
	setSpeedUnit := func(u string) {
		if strings.EqualFold(state.speedUnit, u) {
			return
		}
		state.speedUnit = u
		savePrefs(state)
		if state.table != nil {
			state.table.Refresh()
		}
		redrawCharts(state)
		go func() {
			time.Sleep(30 * time.Millisecond)
			fyne.Do(func() { buildMenus(state, fileLabel) })
		}()
	}
	suKbps := fyne.NewMenuItem(speedUnitLabelFor("kbps"), func() { setSpeedUnit("kbps") })
	suKBps := fyne.NewMenuItem(speedUnitLabelFor("kBps"), func() { setSpeedUnit("kBps") })
	suMbps := fyne.NewMenuItem(speedUnitLabelFor("Mbps"), func() { setSpeedUnit("Mbps") })
	suMBps := fyne.NewMenuItem(speedUnitLabelFor("MBps"), func() { setSpeedUnit("MBps") })
	suGbps := fyne.NewMenuItem(speedUnitLabelFor("Gbps"), func() { setSpeedUnit("Gbps") })
	suGBps := fyne.NewMenuItem(speedUnitLabelFor("GBps"), func() { setSpeedUnit("GBps") })
	speedUnitSub := fyne.NewMenu("Speed Unit",
		suKbps, suKBps, suMbps, suMBps, suGbps, suGBps,
	)
	speedUnitSubItem := fyne.NewMenuItem("Speed Unit", nil)
	speedUnitSubItem.ChildMenu = speedUnitSub

	// X-Axis submenu under Settings
	xAxisLabelFor := func(lbl, mode string) string {
		if strings.EqualFold(state.xAxisMode, mode) {
			return lbl + " ✓"
		}
		return lbl
	}
	setXAxis := func(mode string) {
		if strings.EqualFold(state.xAxisMode, mode) {
			return
		}
		state.xAxisMode = mode
		savePrefs(state)
		redrawCharts(state)
		go func() { time.Sleep(30 * time.Millisecond); fyne.Do(func() { buildMenus(state, fileLabel) }) }()
	}
	xaBatch := fyne.NewMenuItem(xAxisLabelFor("Batch", "batch"), func() { setXAxis("batch") })
	xaRunTag := fyne.NewMenuItem(xAxisLabelFor("RunTag", "run_tag"), func() { setXAxis("run_tag") })
	xaTime := fyne.NewMenuItem(xAxisLabelFor("Time", "time"), func() { setXAxis("time") })
	xAxisSub := fyne.NewMenu("X-Axis", xaBatch, xaRunTag, xaTime)
	xAxisSubItem := fyne.NewMenuItem("X-Axis", nil)
	xAxisSubItem.ChildMenu = xAxisSub

	// Y-Scale submenu under Settings
	yScaleLabelFor := func(lbl, mode string) string {
		if strings.EqualFold(state.yScaleMode, mode) {
			return lbl + " ✓"
		}
		return lbl
	}
	setYScale := func(mode string) {
		if strings.EqualFold(state.yScaleMode, mode) {
			return
		}
		state.yScaleMode = mode
		state.useRelative = strings.EqualFold(mode, "relative")
		savePrefs(state)
		redrawCharts(state)
		go func() { time.Sleep(30 * time.Millisecond); fyne.Do(func() { buildMenus(state, fileLabel) }) }()
	}
	ysAbs := fyne.NewMenuItem(yScaleLabelFor("Absolute", "absolute"), func() { setYScale("absolute") })
	ysRel := fyne.NewMenuItem(yScaleLabelFor("Relative", "relative"), func() { setYScale("relative") })
	yScaleSub := fyne.NewMenu("Y-Scale", ysAbs, ysRel)
	yScaleSubItem := fyne.NewMenuItem("Y-Scale", nil)
	yScaleSubItem.ChildMenu = yScaleSub

	// Batches dialog under Settings
	openBatchesDialog := func() {
		entry := widget.NewEntry()
		entry.SetPlaceHolder("Batches (recent N batches)")
		if state.batchesN <= 0 {
			state.batchesN = 50
		}
		entry.SetText(strconv.Itoa(state.batchesN))
		form := &widget.Form{Items: []*widget.FormItem{{Text: "Batches (recent N)", Widget: entry}}, OnSubmit: func() {
			if iv, err := strconv.Atoi(strings.TrimSpace(entry.Text)); err == nil {
				if iv < 10 {
					iv = 10
				}
				if iv > 1000 {
					iv = 1000
				}
				if iv != state.batchesN {
					state.batchesN = iv
					savePrefs(state)
					loadAll(state, fileLabel)
				}
			}
		}}
		d := dialog.NewCustomConfirm("Batches", "Save", "Cancel", form, func(ok bool) {
			if ok {
				form.OnSubmit()
			}
		}, state.window)
		d.Resize(fyne.NewSize(360, 160))
		d.Show()
	}

	// SLA thresholds dialog
	openSLADialog := func() {
		speedEntry := widget.NewEntry()
		speedEntry.SetPlaceHolder("P50 Speed (kbps)")
		speedEntry.SetText(strconv.Itoa(state.slaSpeedThresholdKbps))
		ttfbEntry := widget.NewEntry()
		ttfbEntry.SetPlaceHolder("P95 TTFB (ms)")
		ttfbEntry.SetText(strconv.Itoa(state.slaTTFBThresholdMs))
		form := &widget.Form{
			Items: []*widget.FormItem{
				{Text: "P50 Speed (kbps)", Widget: speedEntry},
				{Text: "P95 TTFB (ms)", Widget: ttfbEntry},
			},
			OnSubmit: func() {
				if iv, err := strconv.Atoi(strings.TrimSpace(speedEntry.Text)); err == nil {
					if iv < 1000 {
						iv = 1000
					}
					if iv > 10_000_000 {
						iv = 10_000_000
					}
					state.slaSpeedThresholdKbps = iv
				}
				if iv, err := strconv.Atoi(strings.TrimSpace(ttfbEntry.Text)); err == nil {
					if iv < 50 {
						iv = 50
					}
					if iv > 10000 {
						iv = 10000
					}
					state.slaTTFBThresholdMs = iv
				}
				savePrefs(state)
				redrawCharts(state)
			},
		}
		d := dialog.NewCustomConfirm("SLA Thresholds", "Save", "Cancel", form, func(ok bool) {
			if ok {
				form.OnSubmit()
			}
		}, state.window)
		d.Resize(fyne.NewSize(380, 200))
		d.Show()
	}
	openLowSpeedDialog := func() {
		entry := widget.NewEntry()
		entry.SetPlaceHolder("Low-Speed Threshold (kbps)")
		if state.lowSpeedThresholdKbps <= 0 {
			state.lowSpeedThresholdKbps = 1000
		}
		entry.SetText(strconv.Itoa(state.lowSpeedThresholdKbps))
		form := &widget.Form{Items: []*widget.FormItem{{Text: "Low-Speed Threshold (kbps)", Widget: entry}}, OnSubmit: func() {
			if iv, err := strconv.Atoi(strings.TrimSpace(entry.Text)); err == nil {
				if iv < 100 {
					iv = 100
				}
				if iv > 100_000_000 {
					iv = 100_000_000
				}
				state.lowSpeedThresholdKbps = iv
				savePrefs(state)
				loadAll(state, fileLabel) // re-analyze summaries
			}
		}}
		d := dialog.NewCustomConfirm("Low-Speed Threshold", "Save", "Cancel", form, func(ok bool) {
			if ok {
				form.OnSubmit()
			}
		}, state.window)
		d.Resize(fyne.NewSize(380, 160))
		d.Show()
	}
	openRollingDialog := func() {
		entry := widget.NewEntry()
		entry.SetPlaceHolder("Rolling Window (N)")
		if state.rollingWindow <= 0 {
			state.rollingWindow = 7
		}
		entry.SetText(strconv.Itoa(state.rollingWindow))
		form := &widget.Form{Items: []*widget.FormItem{{Text: "Rolling Window (N)", Widget: entry}}, OnSubmit: func() {
			if iv, err := strconv.Atoi(strings.TrimSpace(entry.Text)); err == nil {
				if iv < 2 {
					iv = 2
				}
				if iv > 500 {
					iv = 500
				}
				state.rollingWindow = iv
				savePrefs(state)
				redrawCharts(state)
			}
		}}
		d := dialog.NewCustomConfirm("Rolling Window", "Save", "Cancel", form, func(ok bool) {
			if ok {
				form.OnSubmit()
			}
		}, state.window)
		d.Resize(fyne.NewSize(360, 160))
		d.Show()
	}

	settingsMenu := fyne.NewMenu("Settings",
		crosshairToggle,
		hintsToggle,
		pretffbToggle,
		autoHidePretffbToggle,
		fyne.NewMenuItemSeparator(),
		rollingToggle,
		bandToggle,
		fyne.NewMenuItemSeparator(),
		dnsToggle,
		fyne.NewMenuItem("SLA Thresholds…", func() { openSLADialog() }),
		fyne.NewMenuItem("Low-Speed Threshold…", func() { openLowSpeedDialog() }),
		fyne.NewMenuItem("Rolling Window…", func() { openRollingDialog() }),
		fyne.NewMenuItemSeparator(),
		xAxisSubItem,
		yScaleSubItem,
		fyne.NewMenuItem("Batches…", func() { openBatchesDialog() }),
		fyne.NewMenuItemSeparator(),
		speedUnitSubItem,
		fyne.NewMenuItemSeparator(),
		themeSubItem,
	)

	mainMenu := fyne.NewMainMenu(fileMenu, recentMenu, settingsMenu)
	state.window.SetMainMenu(mainMenu)

	canv := state.window.Canvas()
	if canv != nil {
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyO, Modifier: fyne.KeyModifierSuper}, func(fyne.Shortcut) { openFileDialog(state, fileLabel) })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyO, Modifier: fyne.KeyModifierControl}, func(fyne.Shortcut) { openFileDialog(state, fileLabel) })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyR, Modifier: fyne.KeyModifierSuper}, func(fyne.Shortcut) { loadAll(state, fileLabel) })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyR, Modifier: fyne.KeyModifierControl}, func(fyne.Shortcut) { loadAll(state, fileLabel) })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyW, Modifier: fyne.KeyModifierSuper}, func(fyne.Shortcut) { state.window.Close() })
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyW, Modifier: fyne.KeyModifierControl}, func(fyne.Shortcut) { state.window.Close() })
		// Find shortcuts
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyF, Modifier: fyne.KeyModifierSuper}, func(fyne.Shortcut) {
			if state.findEntry != nil {
				canv.Focus(state.findEntry)
				// Try to select all if method exists; otherwise rely on user
				state.findEntry.SetText(state.findEntry.Text) // no-op to keep caret at end
			}
		})
		canv.AddShortcut(&desktop.CustomShortcut{KeyName: fyne.KeyF, Modifier: fyne.KeyModifierControl}, func(fyne.Shortcut) {
			if state.findEntry != nil {
				canv.Focus(state.findEntry)
				state.findEntry.SetText(state.findEntry.Text)
			}
		})
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
	// Use options so low-speed threshold is applied
	ops := analysis.AnalyzeOptions{SituationFilter: "", LowSpeedThresholdKbps: float64(state.lowSpeedThresholdKbps)}
	summaries, err := analysis.AnalyzeRecentResultsFullWithOptions(state.filePath, monitor.SchemaVersion, state.batchesN, ops)
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
	// Prefer situations taken directly from summaries; fall back to map if empty
	state.situations = uniqueSituationsFromSummaries(state.summaries)
	if len(state.situations) == 0 {
		state.situations = uniqueSituationsFromMap(state.runTagSituation)
	}
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
		fmt.Printf("[viewer] situations available: %v\n", opts)
		// Default to All unless a specific situation was previously chosen
		if strings.TrimSpace(state.situation) == "" || strings.EqualFold(state.situation, "All") {
			state.situation = "All"
			state.initializing = true
			state.situationSelect.SetSelected("All")
			state.initializing = false
			fmt.Printf("[viewer] selecting situation: %q (default)\n", "All")
		} else {
			// If saved situation is no longer present in dataset, fall back to All
			found := false
			for _, o := range opts {
				if strings.EqualFold(strings.TrimSpace(o), strings.TrimSpace(state.situation)) {
					found = true
					// Use canonical option string in case of case differences
					state.situation = o
					break
				}
			}
			if found {
				state.initializing = true
				state.situationSelect.SetSelected(state.situation)
				state.initializing = false
				fmt.Printf("[viewer] selecting situation: %q (restored)\n", state.situation)
			} else {
				state.situation = "All"
				state.initializing = true
				state.situationSelect.SetSelected("All")
				state.initializing = false
				fmt.Printf("[viewer] saved situation not found; selecting %q\n", "All")
			}
		}
		// Ensure placeholder reflects actual selection
		state.situationSelect.PlaceHolder = state.situationSelect.Selected
		state.situationSelect.Refresh()
		// Persist the resolved selection so it sticks next launch
		savePrefs(state)
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

// uniqueSituationsFromSummaries returns sorted unique non-empty situations from batch summaries
func uniqueSituationsFromSummaries(rows []analysis.BatchSummary) []string {
	if len(rows) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, r := range rows {
		s := strings.TrimSpace(r.Situation)
		if s != "" {
			set[s] = struct{}{}
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
	if state.situation == "" || strings.EqualFold(state.situation, "All") {
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
		_, chh := chartSize(state)
		if state.speedImgCanvas != nil {
			state.speedImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
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
		_, chh := chartSize(state)
		if state.ttfbImgCanvas != nil {
			state.ttfbImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.ttfbImgCanvas.Refresh()
		}
		if state.ttfbOverlay != nil {
			state.ttfbOverlay.Refresh()
		}
	}
	// Percentiles chart(s) stacked: Overall, IPv4, IPv6; visibility via checkboxes
	// Local self-test chart (single series)
	stImg := renderSelfTestChart(state)
	if stImg != nil {
		if state.selfTestImgCanvas != nil {
			state.selfTestImgCanvas.Image = stImg
			_, chh := chartSize(state)
			state.selfTestImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.selfTestImgCanvas.Refresh()
		}
		if state.selfTestOverlay != nil {
			state.selfTestOverlay.Refresh()
		}
	}

	if state.pctlOverallImg != nil {
		if state.showOverall {
			img := renderPercentilesChartWithFamily(state, "overall")
			if img != nil {
				state.pctlOverallImg.Image = img
				_, chh := chartSize(state)
				state.pctlOverallImg.SetMinSize(fyne.NewSize(0, float32(chh)))
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
				_, chh := chartSize(state)
				state.pctlIPv4Img.SetMinSize(fyne.NewSize(0, float32(chh)))
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
				_, chh := chartSize(state)
				state.pctlIPv6Img.SetMinSize(fyne.NewSize(0, float32(chh)))
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
				_, chh := chartSize(state)
				state.tpctlOverallImg.SetMinSize(fyne.NewSize(0, float32(chh)))
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
				_, chh := chartSize(state)
				state.tpctlIPv4Img.SetMinSize(fyne.NewSize(0, float32(chh)))
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
				_, chh := chartSize(state)
				state.tpctlIPv6Img.SetMinSize(fyne.NewSize(0, float32(chh)))
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
	// Tail Heaviness (P99/P50 Speed)
	trImg := renderTailHeavinessChart(state)
	if trImg != nil {
		if state.tailRatioImgCanvas != nil {
			state.tailRatioImgCanvas.Image = trImg
			_, chh := chartSize(state)
			state.tailRatioImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.tailRatioImgCanvas.Refresh()
			if state.tailRatioOverlay != nil {
				state.tailRatioOverlay.Refresh()
			}
		}
	}
	// TTFB Tail Heaviness (P95/P50)
	ttrImg := renderTTFBTailHeavinessChart(state)
	if ttrImg != nil {
		if state.ttfbTailRatioImgCanvas != nil {
			state.ttfbTailRatioImgCanvas.Image = ttrImg
			_, chh := chartSize(state)
			state.ttfbTailRatioImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.ttfbTailRatioImgCanvas.Refresh()
			if state.ttfbTailRatioOverlay != nil {
				state.ttfbTailRatioOverlay.Refresh()
			}
		}
	}
	// Family Delta – Speed
	sdImg := renderFamilyDeltaSpeedChart(state)
	if sdImg != nil {
		if state.speedDeltaImgCanvas != nil {
			state.speedDeltaImgCanvas.Image = sdImg
			_, chh := chartSize(state)
			state.speedDeltaImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.speedDeltaImgCanvas.Refresh()
			if state.speedDeltaOverlay != nil {
				state.speedDeltaOverlay.Refresh()
			}
		}
	}
	// Family Delta – TTFB
	tdImg := renderFamilyDeltaTTFBChart(state)
	if tdImg != nil {
		if state.ttfbDeltaImgCanvas != nil {
			state.ttfbDeltaImgCanvas.Image = tdImg
			_, chh := chartSize(state)
			state.ttfbDeltaImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.ttfbDeltaImgCanvas.Refresh()
			if state.ttfbDeltaOverlay != nil {
				state.ttfbDeltaOverlay.Refresh()
			}
		}
	}
	// Family Delta – Speed %
	sdpImg := renderFamilyDeltaSpeedPctChart(state)
	if sdpImg != nil {
		if state.speedDeltaPctImgCanvas != nil {
			state.speedDeltaPctImgCanvas.Image = sdpImg
			_, chh := chartSize(state)
			state.speedDeltaPctImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.speedDeltaPctImgCanvas.Refresh()
			if state.speedDeltaPctOverlay != nil {
				state.speedDeltaPctOverlay.Refresh()
			}
		}
	}
	// Family Delta – TTFB %
	tdpImg := renderFamilyDeltaTTFBPctChart(state)
	if tdpImg != nil {
		if state.ttfbDeltaPctImgCanvas != nil {
			state.ttfbDeltaPctImgCanvas.Image = tdpImg
			_, chh := chartSize(state)
			state.ttfbDeltaPctImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.ttfbDeltaPctImgCanvas.Refresh()
			if state.ttfbDeltaPctOverlay != nil {
				state.ttfbDeltaPctOverlay.Refresh()
			}
		}
	}
	// SLA Compliance – Speed
	slasImg := renderSLASpeedChart(state)
	if slasImg != nil {
		if state.slaSpeedImgCanvas != nil {
			state.slaSpeedImgCanvas.Image = slasImg
			_, chh := chartSize(state)
			state.slaSpeedImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.slaSpeedImgCanvas.Refresh()
			if state.slaSpeedOverlay != nil {
				state.slaSpeedOverlay.Refresh()
			}
		}
	}
	// SLA Compliance – TTFB
	slatImg := renderSLATTFBChart(state)
	if slatImg != nil {
		if state.slaTTFBImgCanvas != nil {
			state.slaTTFBImgCanvas.Image = slatImg
			_, chh := chartSize(state)
			state.slaTTFBImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.slaTTFBImgCanvas.Refresh()
			if state.slaTTFBOverlay != nil {
				state.slaTTFBOverlay.Refresh()
			}
		}
	}
	// SLA Compliance Delta – Speed
	slaSpdDelta := renderSLASpeedDeltaChart(state)
	if slaSpdDelta != nil {
		if state.slaSpeedDeltaImgCanvas != nil {
			state.slaSpeedDeltaImgCanvas.Image = slaSpdDelta
			_, chh := chartSize(state)
			state.slaSpeedDeltaImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.slaSpeedDeltaImgCanvas.Refresh()
			if state.slaSpeedDeltaOverlay != nil {
				state.slaSpeedDeltaOverlay.Refresh()
			}
		}
	}
	// SLA Compliance Delta – TTFB
	slaTtfbDelta := renderSLATTFBDeltaChart(state)
	if slaTtfbDelta != nil {
		if state.slaTTFBDeltaImgCanvas != nil {
			state.slaTTFBDeltaImgCanvas.Image = slaTtfbDelta
			_, chh := chartSize(state)
			state.slaTTFBDeltaImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.slaTTFBDeltaImgCanvas.Refresh()
			if state.slaTTFBDeltaOverlay != nil {
				state.slaTTFBDeltaOverlay.Refresh()
			}
		}
	}
	// TTFB P95−P50 Gap (ms)
	gapImg := renderTTFBP95GapChart(state)
	if gapImg != nil {
		if state.tpctlP95GapImgCanvas != nil {
			state.tpctlP95GapImgCanvas.Image = gapImg
			_, chh := chartSize(state)
			state.tpctlP95GapImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.tpctlP95GapImgCanvas.Refresh()
			if state.tpctlP95GapOverlay != nil {
				state.tpctlP95GapOverlay.Refresh()
			}
		}
	}
	// Error Rate chart
	erImg := renderErrorRateChart(state)
	if erImg != nil {
		if state.errImgCanvas != nil {
			state.errImgCanvas.Image = erImg
		}
		_, chh := chartSize(state)
		if state.errImgCanvas != nil {
			state.errImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
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
		_, chh := chartSize(state)
		if state.jitterImgCanvas != nil {
			state.jitterImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
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
		_, chh := chartSize(state)
		if state.covImgCanvas != nil {
			state.covImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.covImgCanvas.Refresh()
		}
		if state.covOverlay != nil {
			state.covOverlay.Refresh()
		}
		// Connection setup breakdown charts (DNS, TCP connect, TLS handshake)
		dnsImg := renderDNSLookupChart(state)
		if dnsImg != nil {
			if state.setupDNSImgCanvas != nil {
				state.setupDNSImgCanvas.Image = dnsImg
				_, chh := chartSize(state)
				state.setupDNSImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.setupDNSImgCanvas.Refresh()
			}
		}
		connImg := renderTCPConnectChart(state)
		if connImg != nil {
			if state.setupConnImgCanvas != nil {
				state.setupConnImgCanvas.Image = connImg
				_, chh := chartSize(state)
				state.setupConnImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.setupConnImgCanvas.Refresh()
			}
		}
		tlsImg := renderTLSHandshakeChart(state)
		if tlsImg != nil {
			if state.setupTLSImgCanvas != nil {
				state.setupTLSImgCanvas.Image = tlsImg
				_, chh := chartSize(state)
				state.setupTLSImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.setupTLSImgCanvas.Refresh()
			}
		}
		// Transport/Protocol charts
		pmImg := renderHTTPProtocolMixChart(state)
		if pmImg != nil {
			state.protocolMixImgCanvas.Image = pmImg
			_, chh := chartSize(state)
			state.protocolMixImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.protocolMixImgCanvas.Refresh()
			if state.protocolMixOverlay != nil {
				state.protocolMixOverlay.Refresh()
			}
		}
		pasImg := renderAvgSpeedByHTTPProtocolChart(state)
		if pasImg != nil {
			state.protocolAvgSpeedImgCanvas.Image = pasImg
			_, chh := chartSize(state)
			state.protocolAvgSpeedImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.protocolAvgSpeedImgCanvas.Refresh()
			if state.protocolAvgSpeedOverlay != nil {
				state.protocolAvgSpeedOverlay.Refresh()
			}
		}
		psrImg := renderStallRateByHTTPProtocolChart(state)
		if psrImg != nil {
			state.protocolStallRateImgCanvas.Image = psrImg
			_, chh := chartSize(state)
			state.protocolStallRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.protocolStallRateImgCanvas.Refresh()
			if state.protocolStallRateOverlay != nil {
				state.protocolStallRateOverlay.Refresh()
			}
		}
		perImg := renderErrorRateByHTTPProtocolChart(state)
		if perImg != nil {
			state.protocolErrorRateImgCanvas.Image = perImg
			_, chh := chartSize(state)
			state.protocolErrorRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.protocolErrorRateImgCanvas.Refresh()
			if state.protocolErrorRateOverlay != nil {
				state.protocolErrorRateOverlay.Refresh()
			}
		}
		// Error Share by HTTP Protocol
		pesImg := renderErrorShareByHTTPProtocolChart(state)
		if pesImg != nil {
			state.protocolErrorShareImgCanvas.Image = pesImg
			_, chh := chartSize(state)
			state.protocolErrorShareImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.protocolErrorShareImgCanvas.Refresh()
			if state.protocolErrorShareOverlay != nil {
				state.protocolErrorShareOverlay.Refresh()
			}
		}
		ppImg := renderPartialBodyRateByHTTPProtocolChart(state)
		if ppImg != nil {
			state.protocolPartialRateImgCanvas.Image = ppImg
			_, chh := chartSize(state)
			state.protocolPartialRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.protocolPartialRateImgCanvas.Refresh()
			if state.protocolPartialRateOverlay != nil {
				state.protocolPartialRateOverlay.Refresh()
			}
		}
		tlsMixImg := renderTLSVersionMixChart(state)
		if tlsMixImg != nil {
			state.tlsVersionMixImgCanvas.Image = tlsMixImg
			_, chh := chartSize(state)
			state.tlsVersionMixImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.tlsVersionMixImgCanvas.Refresh()
			if state.tlsVersionMixOverlay != nil {
				state.tlsVersionMixOverlay.Refresh()
			}
		}
		alpnImg := renderALPNMixChart(state)
		if alpnImg != nil {
			state.alpnMixImgCanvas.Image = alpnImg
			_, chh := chartSize(state)
			state.alpnMixImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.alpnMixImgCanvas.Refresh()
			if state.alpnMixOverlay != nil {
				state.alpnMixOverlay.Refresh()
			}
		}
		chunkedImg := renderChunkedTransferRateChart(state)
		if chunkedImg != nil {
			state.chunkedRateImgCanvas.Image = chunkedImg
			_, chh := chartSize(state)
			state.chunkedRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
			state.chunkedRateImgCanvas.Refresh()
			if state.chunkedRateOverlay != nil {
				state.chunkedRateOverlay.Refresh()
			}
		}
		// Cache Hit Rate chart
		cacheImg := renderCacheHitRateChart(state)
		if cacheImg != nil {
			if state.cacheImgCanvas != nil {
				state.cacheImgCanvas.Image = cacheImg
			}
			_, chh := chartSize(state)
			if state.cacheImgCanvas != nil {
				state.cacheImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
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
			_, chh := chartSize(state)
			if state.proxyImgCanvas != nil {
				state.proxyImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
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
			_, chh := chartSize(state)
			if state.warmCacheImgCanvas != nil {
				state.warmCacheImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.warmCacheImgCanvas.Refresh()
			}
			if state.warmCacheOverlay != nil {
				state.warmCacheOverlay.Refresh()
			}
		}
		// Low-Speed Time Share chart
		lssImg := renderLowSpeedShareChart(state)
		if lssImg != nil {
			if state.lowSpeedImgCanvas != nil {
				state.lowSpeedImgCanvas.Image = lssImg
			}
			_, chh := chartSize(state)
			if state.lowSpeedImgCanvas != nil {
				state.lowSpeedImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.lowSpeedImgCanvas.Refresh()
			}
			if state.lowSpeedOverlay != nil {
				state.lowSpeedOverlay.Refresh()
			}
		}
		// Stall Rate chart
		srImg := renderStallRateChart(state)
		if srImg != nil {
			if state.stallRateImgCanvas != nil {
				state.stallRateImgCanvas.Image = srImg
			}
			_, chh := chartSize(state)
			if state.stallRateImgCanvas != nil {
				state.stallRateImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.stallRateImgCanvas.Refresh()
			}
			if state.stallRateOverlay != nil {
				state.stallRateOverlay.Refresh()
			}
		}
		// Pre‑TTFB Stall Rate chart
		pretffbImg := renderPreTTFBStallRateChart(state)
		if pretffbImg != nil {
			if state.pretffbImgCanvas != nil {
				state.pretffbImgCanvas.Image = pretffbImg
			}
			_, chh := chartSize(state)
			if state.pretffbImgCanvas != nil {
				state.pretffbImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.pretffbImgCanvas.Refresh()
			}
			if state.pretffbOverlay != nil {
				state.pretffbOverlay.Refresh()
			}
			// Determine if metric is all zeros across all visible series
			allZero := true
			for _, r := range filteredSummaries(state) {
				if state.showOverall && r.PreTTFBStallRatePct > 0 {
					allZero = false
					break
				}
				if state.showIPv4 && r.IPv4 != nil && r.IPv4.PreTTFBStallRatePct > 0 {
					allZero = false
					break
				}
				if state.showIPv6 && r.IPv6 != nil && r.IPv6.PreTTFBStallRatePct > 0 {
					allZero = false
					break
				}
			}
			if state.pretffbBlock != nil {
				// Hide only if user enabled auto-hide and metric is all zero, or if user disabled showing the chart entirely
				if (!state.showPreTTFB) || (state.autoHidePreTTFB && allZero) {
					state.pretffbBlock.Hide()
				} else {
					state.pretffbBlock.Show()
				}
			}
		}
		// Avg Stall Time chart
		stImg := renderStallTimeChart(state)
		if stImg != nil {
			if state.stallTimeImgCanvas != nil {
				state.stallTimeImgCanvas.Image = stImg
			}
			_, chh := chartSize(state)
			if state.stallTimeImgCanvas != nil {
				state.stallTimeImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.stallTimeImgCanvas.Refresh()
			}
			if state.stallTimeOverlay != nil {
				state.stallTimeOverlay.Refresh()
			}
		}
		// Partial Body Rate chart
		pbrImg := renderPartialBodyRateChart(state)
		if pbrImg != nil {
			if state.partialBodyImgCanvas != nil {
				state.partialBodyImgCanvas.Image = pbrImg
			}
			_, chh := chartSize(state)
			if state.partialBodyImgCanvas != nil {
				state.partialBodyImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.partialBodyImgCanvas.Refresh()
			}
			if state.partialBodyOverlay != nil {
				state.partialBodyOverlay.Refresh()
			}
		}
		// Stalled Requests Count (interim) chart
		scImg := renderStallCountChart(state)
		if scImg != nil {
			if state.stallCountImgCanvas != nil {
				state.stallCountImgCanvas.Image = scImg
			}
			_, chh := chartSize(state)
			if state.stallCountImgCanvas != nil {
				state.stallCountImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
				state.stallCountImgCanvas.Refresh()
			}
			if state.stallCountOverlay != nil {
				state.stallCountOverlay.Refresh()
			}
		}
		// Plateau Count chart
		plcImg := renderPlateauCountChart(state)
		if plcImg != nil {
			if state.plCountImgCanvas != nil {
				state.plCountImgCanvas.Image = plcImg
			}
			_, chh := chartSize(state)
			if state.plCountImgCanvas != nil {
				state.plCountImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
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
			_, chh := chartSize(state)
			if state.plLongestImgCanvas != nil {
				state.plLongestImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
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
			_, chh := chartSize(state)
			if state.plStableImgCanvas != nil {
				state.plStableImgCanvas.SetMinSize(fyne.NewSize(0, float32(chh)))
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
		w, h := chartSize(state)
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
			return b.IPv4.AvgP50TTFBMs
		}, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgP90TTFBMs
		}, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgP95TTFBMs
		}, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgP99TTFBMs
		}, chart.ColorRed)
	case "ipv6":
		add("P50", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP50TTFBMs
		}, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP90TTFBMs
		}, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP95TTFBMs
		}, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP99TTFBMs
		}, chart.ColorRed)
	default:
		add("P50", func(b analysis.BatchSummary) float64 { return b.AvgP50TTFBMs }, chart.ColorBlue)
		add("P90", func(b analysis.BatchSummary) float64 { return b.AvgP90TTFBMs }, chart.ColorGreen)
		add("P95", func(b analysis.BatchSummary) float64 { return b.AvgP95TTFBMs }, chart.ColorAlternateGray)
		add("P99", func(b analysis.BatchSummary) float64 { return b.AvgP99TTFBMs }, chart.ColorRed)
	}

	// Initialize to a non-nil zero range to avoid go-chart calling methods on a nil pointer
	yAxisRange := &chart.ContinuousRange{}
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

	var titlePrefix string
	switch fam {
	case "ipv4":
		titlePrefix = "IPv4 "
	case "ipv6":
		titlePrefix = "IPv6 "
	default:
		titlePrefix = "Overall "
	}
	ch := chart.Chart{
		Title:      fmt.Sprintf("%sTTFB Percentiles (ms)", titlePrefix),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width = cw
	ch.Height = chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		fmt.Printf("[viewer] renderStallRateChart: render error: %v\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: TTFB percentiles capture latency distribution. Wider gaps indicate latency spikes.")
	}
	// always watermark with active situation
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderTTFBTailHeavinessChart plots TTFB tail heaviness as P95/P50 ratio (unitless) for Overall/IPv4/IPv6.
func renderTTFBTailHeavinessChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
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
		add("Overall", func(b analysis.BatchSummary) float64 {
			if b.AvgP50TTFBMs <= 0 {
				return math.NaN()
			}
			return b.AvgP95TTFBMs / b.AvgP50TTFBMs
		}, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil || b.IPv4.AvgP50TTFBMs <= 0 {
				return math.NaN()
			}
			return b.IPv4.AvgP95TTFBMs / b.IPv4.AvgP50TTFBMs
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil || b.IPv6.AvgP50TTFBMs <= 0 {
				return math.NaN()
			}
			return b.IPv6.AvgP95TTFBMs / b.IPv6.AvgP50TTFBMs
		}, chart.ColorGreen)
	}
	// Initialize to a non-nil zero range to avoid go-chart calling methods on a nil pointer
	yAxisRange := &chart.ContinuousRange{}
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 0.1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
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
	ch := chart.Chart{Title: "TTFB Tail Heaviness (P95/P50)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ratio", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		fmt.Printf("[viewer] renderStallTimeChart: render error: %v\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Ratio of P95 to P50 TTFB. Higher means heavier latency tail.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderTTFBP95GapChart plots (P95−P50) TTFB gap in ms for Overall/IPv4/IPv6.
func renderTTFBP95GapChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
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
			if math.IsNaN(v) {
				ys[i] = math.NaN()
				continue
			}
			if v < 0 {
				v = 0
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

	// Overall/IPv4/IPv6 (respect visibility toggles)
	if state.showOverall {
		add("Overall", func(b analysis.BatchSummary) float64 { return math.Max(0, b.AvgP95TTFBMs-b.AvgP50TTFBMs) }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return math.NaN()
			}
			return math.Max(0, b.IPv4.AvgP95TTFBMs-b.IPv4.AvgP50TTFBMs)
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return math.NaN()
			}
			return math.Max(0, b.IPv6.AvgP95TTFBMs-b.IPv6.AvgP50TTFBMs)
		}, chart.ColorGreen)
	}

	// Initialize to a non-nil zero range to avoid go-chart calling methods on a nil pointer
	yAxisRange := &chart.ContinuousRange{}
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
	ch := chart.Chart{
		Title:      "TTFB P95−P50 Gap (ms)",
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		fmt.Printf("[viewer] renderStallCountChart: render error: %v\n", err)
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Gap = P95−P50. Larger gaps = heavier latency tails.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderCacheHitRateChart draws CacheHitRatePct per batch (overall/IPv4/IPv6).
func renderCacheHitRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Cache Hit Rate (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: Cache hit rate. Higher can mean content already cached near you.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderProxySuspectedRateChart draws ProxySuspectedRatePct per batch (overall/IPv4/IPv6).
func renderProxySuspectedRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Proxy Suspected Rate (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: How often a proxy is suspected. Spikes can indicate transit via middleboxes.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderWarmCacheSuspectedRateChart draws WarmCacheSuspectedRatePct per batch (overall/IPv4/IPv6).
func renderWarmCacheSuspectedRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Warm Cache Suspected Rate (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: Warm-cache suspected rate. Higher suggests repeated content or prior fetch effects.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderLowSpeedShareChart draws Low-Speed Time Share (%) per batch (overall/IPv4/IPv6).
func renderLowSpeedShareChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.LowSpeedTimeSharePct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.LowSpeedTimeSharePct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.LowSpeedTimeSharePct
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Low-Speed Time Share (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: % of time below the configured Low-Speed Threshold.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderStallRateChart draws Stall Rate (%) per batch (overall/IPv4/IPv6).
func renderStallRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			// Keep zeros as real data points; only drop negatives or missing.
			if v < 0 || math.IsNaN(v) {
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.StallRatePct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.StallRatePct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.StallRatePct
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Stall Rate (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: % of requests that experienced any stall.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderPartialBodyRateChart draws Partial Body Rate (%) per batch (overall/IPv4/IPv6).
func renderPartialBodyRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v < 0 || math.IsNaN(v) {
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.PartialBodyRatePct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.PartialBodyRatePct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.PartialBodyRatePct
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Partial Body Rate (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: % of requests with incomplete body (CL mismatch or early EOF).")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderPreTTFBStallRateChart draws Pre‑TTFB Stall Rate (%) per batch (overall/IPv4/IPv6).
func renderPreTTFBStallRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			if v < 0 || math.IsNaN(v) {
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.PreTTFBStallRatePct }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.PreTTFBStallRatePct
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.PreTTFBStallRatePct
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Pre‑TTFB Stall Rate (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: % of requests aborted before first byte due to stall (opt-in feature).")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderStallTimeChart draws Avg Stall Time (ms) per batch (overall/IPv4/IPv6).
func renderStallTimeChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			v := sel(r)
			// Keep zeros; only skip negatives or NaN
			if v < 0 || math.IsNaN(v) {
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgStallElapsedMs }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgStallElapsedMs
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgStallElapsedMs
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Avg Stall Time (ms)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Average stalled time per request. High values indicate severe buffering or outages.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// chartSize computes a chart size based on the current window width so charts use more X-axis space.
func chartSize(state *uiState) (int, int) {
	// Headless/screenshot mode: allow tests to override width for exact checks.
	if state == nil || state.window == nil || state.window.Canvas() == nil {
		if screenshotWidthOverride > 0 {
			w := screenshotWidthOverride
			if w < 800 {
				w = 800
			}
			h := int(float32(w) * 0.33)
			if h < 280 {
				h = 280
			}
			if h > 520 {
				h = 520
			}
			return w, h
		}
		return 1100, 340
	}
	// UI mode: use the full canvas width for charts (no artificial shrink).
	sz := state.window.Canvas().Size()
	w := int(sz.Width)
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
		w, h := chartSize(state)
		return blank(w, h)
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

	var yAxisRange chart.Range
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
		Title:      fmt.Sprintf("Avg Speed (%s)", unitName),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: unitName, Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	themeChart(&ch)
	// Add rolling overlays (mean line and ±1 std band) if enabled and have enough points
	if state.showRolling && len(rows) >= 2 && state.rollingWindow >= 2 {
		bandLabel := ""
		if state.showRollingBand {
			bandLabel = fmt.Sprintf("Rolling μ±1σ (%d)", state.rollingWindow)
		}
		labelUsed := false
		// Build arrays for overall/IPv4/IPv6 in base unit (already factored)
		build := func(sel func(analysis.BatchSummary) (float64, bool)) ([]float64, []bool) {
			ys := make([]float64, len(rows))
			ok := make([]bool, len(rows))
			for i, r := range rows {
				v, valid := sel(r)
				if valid && !math.IsNaN(v) && v > 0 {
					ys[i] = v
					ok[i] = true
				}
			}
			return ys, ok
		}
		rolling := func(vals []float64, oks []bool, win int) ([]float64, []float64) {
			n := len(vals)
			if win > n {
				win = n
			}
			m := make([]float64, n)
			s := make([]float64, n)
			var sum, sumsq float64
			count := 0
			// initialize first window
			for i := 0; i < n; i++ {
				// slide window to include i and keep at most win
				if oks[i] {
					sum += vals[i]
					sumsq += vals[i] * vals[i]
					count++
				}
				if i >= win {
					// remove i-win
					j := i - win
					if oks[j] {
						sum -= vals[j]
						sumsq -= vals[j] * vals[j]
						count--
					}
				}
				if count >= 2 {
					mu := sum / float64(count)
					varVar := sumsq/float64(count) - mu*mu
					if varVar < 0 {
						varVar = 0
					}
					m[i] = mu
					s[i] = math.Sqrt(varVar)
				} else {
					m[i] = math.NaN()
					s[i] = math.NaN()
				}
			}
			return m, s
		}
		// Overall
		if state.showOverall {
			ys, ok := build(func(b analysis.BatchSummary) (float64, bool) { return b.AvgSpeed * factor, b.AvgSpeed > 0 })
			m, s := rolling(ys, ok, state.rollingWindow)
			addRollingSeriesSpeed(&ch, timeMode, times, xs, m, s, chart.ColorAlternateGray, state.showRollingBand, bandLabel)
			if bandLabel != "" {
				labelUsed = true
				bandLabel = ""
			}
		}
		if state.showIPv4 {
			ys, ok := build(func(b analysis.BatchSummary) (float64, bool) {
				if b.IPv4 == nil {
					return 0, false
				}
				return b.IPv4.AvgSpeed * factor, b.IPv4.AvgSpeed > 0
			})
			m, s := rolling(ys, ok, state.rollingWindow)
			lab := ""
			if !labelUsed {
				lab = bandLabel
			}
			addRollingSeriesSpeed(&ch, timeMode, times, xs, m, s, chart.ColorBlue, state.showRollingBand, lab)
			if lab != "" {
				labelUsed = true
				bandLabel = ""
			}
		}
		if state.showIPv6 {
			ys, ok := build(func(b analysis.BatchSummary) (float64, bool) {
				if b.IPv6 == nil {
					return 0, false
				}
				return b.IPv6.AvgSpeed * factor, b.IPv6.AvgSpeed > 0
			})
			m, s := rolling(ys, ok, state.rollingWindow)
			lab := ""
			if !labelUsed {
				lab = bandLabel
			}
			addRollingSeriesSpeed(&ch, timeMode, times, xs, m, s, chart.ColorGreen, state.showRollingBand, lab)
			if lab != "" {
				labelUsed = true
				bandLabel = ""
			}
		}
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
		img = drawHint(img, "Hint: Speed trends. Drops may indicate congestion, Wi‑Fi issues, or ISP problems.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderSelfTestChart plots the local loopback throughput baseline (from meta) per batch.
func renderSelfTestChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	unitName, factor := speedUnitNameAndFactor(state.speedUnit)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)

	ys := make([]float64, len(rows))
	minY := math.MaxFloat64
	maxY := -math.MaxFloat64
	valid := 0
	for i, r := range rows {
		v := r.LocalSelfTestKbps * factor
		if v <= 0 || math.IsNaN(v) {
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
	st := pointStyle(chart.ColorAlternateGray)
	if valid == 1 {
		st.DotWidth = 6
	}
	var series chart.Series
	if timeMode {
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.TimeSeries{Name: "Baseline", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st}
		} else {
			series = chart.TimeSeries{Name: "Baseline", XValues: times, YValues: ys, Style: st}
		}
	} else {
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.ContinuousSeries{Name: "Baseline", XValues: []float64{xs[0], x2}, YValues: ys, Style: st}
		} else {
			series = chart.ContinuousSeries{Name: "Baseline", XValues: xs, YValues: ys, Style: st}
		}
	}

	// Y axis
	var yAxisRange chart.Range = &chart.ContinuousRange{Min: 0, Max: 1}
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
		if maxY <= 0 {
			maxY = 1
		}
		_, nMax := niceAxisBounds(0, maxY)
		yAxisRange = &chart.ContinuousRange{Min: 0, Max: nMax}
		yTicks = nil
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
		Title:      fmt.Sprintf("Local Throughput Self-Test (%s)", unitName),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: unitName, Range: yAxisRange, Ticks: yTicks},
		Series:     []chart.Series{series},
	}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Local loopback throughput baseline. If this is low, your device/OS may be the bottleneck.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

func renderTTFBChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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

	var yAxisRange chart.Range
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
		Title:      "Avg TTFB (ms)",
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	themeChart(&ch)
	// Rolling overlays for TTFB (mean line and ±1 std band)
	if state.showRolling && len(rows) >= 2 && state.rollingWindow >= 2 {
		bandLabel := ""
		if state.showRollingBand {
			bandLabel = fmt.Sprintf("Rolling μ±1σ (%d)", state.rollingWindow)
		}
		labelUsed := false
		build := func(sel func(analysis.BatchSummary) (float64, bool)) ([]float64, []bool) {
			ys := make([]float64, len(rows))
			ok := make([]bool, len(rows))
			for i, r := range rows {
				v, valid := sel(r)
				if valid && !math.IsNaN(v) && v > 0 {
					ys[i] = v
					ok[i] = true
				}
			}
			return ys, ok
		}
		rolling := func(vals []float64, oks []bool, win int) ([]float64, []float64) {
			n := len(vals)
			if win > n {
				win = n
			}
			m := make([]float64, n)
			s := make([]float64, n)
			var sum, sumsq float64
			count := 0
			for i := 0; i < n; i++ {
				if oks[i] {
					sum += vals[i]
					sumsq += vals[i] * vals[i]
					count++
				}
				if i >= win {
					j := i - win
					if oks[j] {
						sum -= vals[j]
						sumsq -= vals[j] * vals[j]
						count--
					}
				}
				if count >= 2 {
					mu := sum / float64(count)
					v := sumsq/float64(count) - mu*mu
					if v < 0 {
						v = 0
					}
					m[i] = mu
					s[i] = math.Sqrt(v)
				} else {
					m[i] = math.NaN()
					s[i] = math.NaN()
				}
			}
			return m, s
		}
		if state.showOverall {
			ys, ok := build(func(b analysis.BatchSummary) (float64, bool) { return b.AvgTTFB, b.AvgTTFB > 0 })
			m, s := rolling(ys, ok, state.rollingWindow)
			addRollingSeriesTTFB(&ch, timeMode, times, xs, m, s, chart.ColorAlternateGray, state.showRollingBand, bandLabel)
			if bandLabel != "" {
				labelUsed = true
				bandLabel = ""
			}
		}
		if state.showIPv4 {
			ys, ok := build(func(b analysis.BatchSummary) (float64, bool) {
				if b.IPv4 == nil {
					return 0, false
				}
				return b.IPv4.AvgTTFB, b.IPv4.AvgTTFB > 0
			})
			m, s := rolling(ys, ok, state.rollingWindow)
			lab := ""
			if !labelUsed {
				lab = bandLabel
			}
			addRollingSeriesTTFB(&ch, timeMode, times, xs, m, s, chart.ColorBlue, state.showRollingBand, lab)
			if lab != "" {
				labelUsed = true
				bandLabel = ""
			}
		}
		if state.showIPv6 {
			ys, ok := build(func(b analysis.BatchSummary) (float64, bool) {
				if b.IPv6 == nil {
					return 0, false
				}
				return b.IPv6.AvgTTFB, b.IPv6.AvgTTFB > 0
			})
			m, s := rolling(ys, ok, state.rollingWindow)
			lab := ""
			if !labelUsed {
				lab = bandLabel
			}
			addRollingSeriesTTFB(&ch, timeMode, times, xs, m, s, chart.ColorGreen, state.showRollingBand, lab)
			if lab != "" {
				labelUsed = true
				bandLabel = ""
			}
		}
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
		img = drawHint(img, "Hint: TTFB reflects latency. Spikes often point to DNS/TLS/connect issues or remote slowness.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// addRollingSeriesSpeed adds mean line and ±1 std fill band for Speed chart.
func addRollingSeriesSpeed(ch *chart.Chart, timeMode bool, times []time.Time, xs []float64, mean, std []float64, col drawing.Color, showBand bool, bandLabel string) {
	if ch == nil || len(mean) == 0 {
		return
	}
	lineColor := col.WithAlpha(220)
	bandColor := col.WithAlpha(60)
	// Use the chart's canvas/background color for band cutouts so it matches the active theme
	bgCol := ch.Canvas.FillColor
	// Build upper/lower arrays where both mean and std are valid
	upper := make([]float64, len(mean))
	lower := make([]float64, len(mean))
	for i := range mean {
		if math.IsNaN(mean[i]) || math.IsNaN(std[i]) {
			upper[i] = math.NaN()
			lower[i] = math.NaN()
		} else {
			upper[i] = mean[i] + std[i]
			lower[i] = mean[i] - std[i]
		}
	}
	if timeMode {
		// Pad single-point case
		ux, lx := times, times
		uvals, lvals := upper, lower
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ux = []time.Time{times[0], t2}
			lx = ux
			u0 := upper[0]
			l0 := lower[0]
			uvals = []float64{u0, u0}
			lvals = []float64{l0, l0}
		}
		if showBand {
			// Draw upper translucent fill
			ch.Series = append(ch.Series, chart.TimeSeries{Name: bandLabel, XValues: ux, YValues: uvals, Style: chart.Style{StrokeWidth: 0, DotWidth: 0, FillColor: bandColor}})
			// Cut out the area below lower using white fill (plot background)
			ch.Series = append(ch.Series, chart.TimeSeries{Name: "", XValues: lx, YValues: lvals, Style: chart.Style{StrokeWidth: 0, DotWidth: 0, FillColor: bgCol}})
		}
		// Mean line on top
		mx := times
		mvals := mean
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			mx = []time.Time{times[0], t2}
			mvals = []float64{mean[0], mean[0]}
		}
		ch.Series = append(ch.Series, chart.TimeSeries{Name: "Rolling Mean", XValues: mx, YValues: mvals, Style: chart.Style{StrokeWidth: 1.5, StrokeColor: lineColor, DotWidth: 0}})
	} else {
		ux, lx := xs, xs
		uvals, lvals := upper, lower
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ux = []float64{xs[0], x2}
			lx = ux
			u0 := upper[0]
			l0 := lower[0]
			uvals = []float64{u0, u0}
			lvals = []float64{l0, l0}
		}
		if showBand {
			ch.Series = append(ch.Series, chart.ContinuousSeries{Name: bandLabel, XValues: ux, YValues: uvals, Style: chart.Style{StrokeWidth: 0, DotWidth: 0, FillColor: bandColor}})
			ch.Series = append(ch.Series, chart.ContinuousSeries{Name: "", XValues: lx, YValues: lvals, Style: chart.Style{StrokeWidth: 0, DotWidth: 0, FillColor: bgCol}})
		}
		mx := xs
		mvals := mean
		if len(xs) == 1 {
			x2 := xs[0] + 1
			mx = []float64{xs[0], x2}
			mvals = []float64{mean[0], mean[0]}
		}
		ch.Series = append(ch.Series, chart.ContinuousSeries{Name: "Rolling Mean", XValues: mx, YValues: mvals, Style: chart.Style{StrokeWidth: 1.5, StrokeColor: lineColor, DotWidth: 0}})
	}
}

// addRollingSeriesTTFB adds mean line and ±1 std fill band for TTFB chart.
func addRollingSeriesTTFB(ch *chart.Chart, timeMode bool, times []time.Time, xs []float64, mean, std []float64, col drawing.Color, showBand bool, bandLabel string) {
	if ch == nil || len(mean) == 0 {
		return
	}
	lineColor := col.WithAlpha(220)
	bandColor := col.WithAlpha(60)
	// Theme-aware background for band cutout
	bgCol := ch.Canvas.FillColor
	upper := make([]float64, len(mean))
	lower := make([]float64, len(mean))
	for i := range mean {
		if math.IsNaN(mean[i]) || math.IsNaN(std[i]) {
			upper[i] = math.NaN()
			lower[i] = math.NaN()
		} else {
			upper[i] = mean[i] + std[i]
			lower[i] = mean[i] - std[i]
		}
	}
	if timeMode {
		ux, lx := times, times
		uvals, lvals := upper, lower
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ux = []time.Time{times[0], t2}
			lx = ux
			u0 := upper[0]
			l0 := lower[0]
			uvals = []float64{u0, u0}
			lvals = []float64{l0, l0}
		}
		if showBand {
			ch.Series = append(ch.Series, chart.TimeSeries{Name: bandLabel, XValues: ux, YValues: uvals, Style: chart.Style{StrokeWidth: 0, DotWidth: 0, FillColor: bandColor}})
			ch.Series = append(ch.Series, chart.TimeSeries{Name: "", XValues: lx, YValues: lvals, Style: chart.Style{StrokeWidth: 0, DotWidth: 0, FillColor: bgCol}})
		}
		mx := times
		mvals := mean
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			mx = []time.Time{times[0], t2}
			mvals = []float64{mean[0], mean[0]}
		}
		ch.Series = append(ch.Series, chart.TimeSeries{Name: "Rolling Mean", XValues: mx, YValues: mvals, Style: chart.Style{StrokeWidth: 1.5, StrokeColor: lineColor, DotWidth: 0}})
	} else {
		ux, lx := xs, xs
		uvals, lvals := upper, lower
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ux = []float64{xs[0], x2}
			lx = ux
			u0 := upper[0]
			l0 := lower[0]
			uvals = []float64{u0, u0}
			lvals = []float64{l0, l0}
		}
		if showBand {
			ch.Series = append(ch.Series, chart.ContinuousSeries{Name: bandLabel, XValues: ux, YValues: uvals, Style: chart.Style{StrokeWidth: 0, DotWidth: 0, FillColor: bandColor}})
			ch.Series = append(ch.Series, chart.ContinuousSeries{Name: "", XValues: lx, YValues: lvals, Style: chart.Style{StrokeWidth: 0, DotWidth: 0, FillColor: bgCol}})
		}
		mx := xs
		mvals := mean
		if len(xs) == 1 {
			x2 := xs[0] + 1
			mx = []float64{xs[0], x2}
			mvals = []float64{mean[0], mean[0]}
		}
		ch.Series = append(ch.Series, chart.ContinuousSeries{Name: "Rolling Mean", XValues: mx, YValues: mvals, Style: chart.Style{StrokeWidth: 1.5, StrokeColor: lineColor, DotWidth: 0}})
	}
}

// renderStallCountChart plots the interim stalled requests count per batch = round(Lines * StallRatePct / 100).
func renderStallCountChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	// Three series overall/ipv4/ipv6
	series := []chart.Series{}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	add := func(name string, get func(analysis.BatchSummary) (num int, ok bool), col drawing.Color) {
		ys := make([]float64, len(rows))
		valid := 0
		for i, r := range rows {
			n, ok := get(r)
			if !ok {
				ys[i] = math.NaN()
				continue
			}
			v := float64(n)
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
		add("Overall", func(b analysis.BatchSummary) (int, bool) {
			if b.Lines <= 0 {
				return 0, false
			}
			// zero is valid when StallRatePct == 0
			val := int(math.Round(float64(b.Lines) * math.Max(b.StallRatePct, 0) / 100.0))
			return val, true
		}, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) (int, bool) {
			if b.IPv4 == nil || b.IPv4.Lines <= 0 {
				return 0, false
			}
			val := int(math.Round(float64(b.IPv4.Lines) * math.Max(b.IPv4.StallRatePct, 0) / 100.0))
			return val, true
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) (int, bool) {
			if b.IPv6 == nil || b.IPv6.Lines <= 0 {
				return 0, false
			}
			val := int(math.Round(float64(b.IPv6.Lines) * math.Max(b.IPv6.StallRatePct, 0) / 100.0))
			return val, true
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Stalled Requests Count", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "count", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Estimated stalled requests per batch. Derived from Lines × Stall Rate%.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderErrorRateChart draws error percentage per batch for overall, IPv4, IPv6.
func renderErrorRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
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

	var yAxisRange chart.Range
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
		Title:      "Error Rate (%)",
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: Error rate per batch (overall and per‑family). Spikes often correlate with outages or auth/firewall issues.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderJitterChart draws AvgJitterPct per batch for overall, IPv4, IPv6.
func renderJitterChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Jitter (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: Jitter measures volatility per batch. Lower is more stable.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderDNSLookupChart draws average DNS lookup time (ms) for overall, IPv4, IPv6.
func renderDNSLookupChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgDNSMs }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgDNSMs
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgDNSMs
		}, chart.ColorGreen)
	}
	// Optional legacy overlay from dns_time_ms as dashed series
	if state.showDNSLegacy {
		addDashed := func(name string, sel func(analysis.BatchSummary) float64, col drawing.Color) {
			// Build series similarly to add() but with dashed stroke and thinner dots
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
			st := chart.Style{StrokeColor: col, StrokeWidth: 1.0, StrokeDashArray: []float64{4, 3}, DotWidth: 3, DotColor: col}
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
			addDashed("Overall (dns_time_ms)", func(b analysis.BatchSummary) float64 { return b.AvgDNSLegacyMs }, chart.ColorAlternateGray)
		}
		if state.showIPv4 {
			addDashed("IPv4 (dns_time_ms)", func(b analysis.BatchSummary) float64 {
				if b.IPv4 == nil {
					return 0
				}
				return b.IPv4.AvgDNSLegacyMs
			}, chart.ColorBlue)
		}
		if state.showIPv6 {
			addDashed("IPv6 (dns_time_ms)", func(b analysis.BatchSummary) float64 {
				if b.IPv6 == nil {
					return 0
				}
				return b.IPv6.AvgDNSLegacyMs
			}, chart.ColorGreen)
		}
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "DNS Lookup Time (ms)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Average DNS resolution time per batch (overall and per-family).")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderTCPConnectChart draws average TCP connect time (ms) for overall, IPv4, IPv6.
func renderTCPConnectChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgConnectMs }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgConnectMs
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgConnectMs
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "TCP Connect Time (ms)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Average TCP connect time per batch (overall and per-family).")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderTLSHandshakeChart draws average TLS handshake time (ms) for overall, IPv4, IPv6.
func renderTLSHandshakeChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgTLSHandshake }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgTLSHandshake
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgTLSHandshake
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "TLS Handshake Time (ms)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Average TLS handshake time per batch (overall and per-family).")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderHTTPProtocolMixChart draws per-protocol percentage lines (0..100%).
func renderHTTPProtocolMixChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	// Collect union of protocol keys
	keySet := map[string]struct{}{}
	for _, r := range rows {
		for k := range r.HTTPProtocolRatePct {
			keySet[k] = struct{}{}
		}
	}
	if len(keySet) == 0 {
		// No protocol data yet
		cw, chh := chartSize(state)
		return drawWatermark(blank(cw, chh), "Situation: "+activeSituationLabel(state))
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	// Build one series per protocol key
	var series []chart.Series
	// Simple palette
	palette := []drawing.Color{chart.ColorBlue, chart.ColorGreen, chart.ColorRed, chart.ColorAlternateGray, chart.ColorBlack, chart.ColorYellow, chart.ColorOrange}
	for i, k := range keys {
		ys := make([]float64, len(rows))
		for j, r := range rows {
			ys[j] = r.HTTPProtocolRatePct[k]
			if ys[j] <= 0 {
				ys[j] = math.NaN()
			}
		}
		st := pointStyle(palette[i%len(palette)])
		name := k
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
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	ch := chart.Chart{Title: "HTTP Protocol Mix (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: &chart.ContinuousRange{Min: 0, Max: 100}, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Percentage of requests by negotiated HTTP protocol.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderAvgSpeedByHTTPProtocolChart draws average speed by protocol.
func renderAvgSpeedByHTTPProtocolChart(state *uiState) image.Image {
	unitName, factor := speedUnitNameAndFactor(state.speedUnit)
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	keySet := map[string]struct{}{}
	for _, r := range rows {
		for k := range r.AvgSpeedByHTTPProtocolKbps {
			keySet[k] = struct{}{}
		}
	}
	if len(keySet) == 0 {
		cw, chh := chartSize(state)
		return drawWatermark(blank(cw, chh), "Situation: "+activeSituationLabel(state))
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	var series []chart.Series
	minY := math.MaxFloat64
	maxY := -math.MaxFloat64
	palette := []drawing.Color{chart.ColorBlue, chart.ColorGreen, chart.ColorRed, chart.ColorAlternateGray, chart.ColorBlack, chart.ColorYellow, chart.ColorOrange}
	for i, k := range keys {
		ys := make([]float64, len(rows))
		valid := 0
		for j, r := range rows {
			v := r.AvgSpeedByHTTPProtocolKbps[k] * factor
			if v <= 0 {
				ys[j] = math.NaN()
			} else {
				ys[j] = v
				if v < minY {
					minY = v
				}
				if v > maxY {
					maxY = v
				}
				valid++
			}
		}
		st := pointStyle(palette[i%len(palette)])
		if valid == 1 {
			st.DotWidth = 6
		}
		name := k
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: fmt.Sprintf("Avg Speed by HTTP Protocol (%s)", unitName), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: unitName, Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Average speed for requests negotiated with each protocol.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

func renderStallRateByHTTPProtocolChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	keySet := map[string]struct{}{}
	for _, r := range rows {
		for k := range r.StallRateByHTTPProtocolPct {
			keySet[k] = struct{}{}
		}
	}
	if len(keySet) == 0 {
		cw, chh := chartSize(state)
		return drawWatermark(blank(cw, chh), "Situation: "+activeSituationLabel(state))
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	var series []chart.Series
	palette := []drawing.Color{chart.ColorBlue, chart.ColorGreen, chart.ColorRed, chart.ColorAlternateGray, chart.ColorBlack, chart.ColorYellow, chart.ColorOrange}
	for i, k := range keys {
		ys := make([]float64, len(rows))
		for j, r := range rows {
			ys[j] = r.StallRateByHTTPProtocolPct[k]
			if ys[j] < 0 {
				ys[j] = math.NaN()
			}
		}
		st := pointStyle(palette[i%len(palette)])
		name := k
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
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	ch := chart.Chart{Title: "Stall Rate by HTTP Protocol (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: &chart.ContinuousRange{Min: 0, Max: 100}, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Percentage of stalled requests per protocol.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

func renderErrorRateByHTTPProtocolChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	keySet := map[string]struct{}{}
	for _, r := range rows {
		for k := range r.ErrorRateByHTTPProtocolPct {
			keySet[k] = struct{}{}
		}
	}
	if len(keySet) == 0 {
		cw, chh := chartSize(state)
		return drawWatermark(blank(cw, chh), "Situation: "+activeSituationLabel(state))
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	var series []chart.Series
	palette := []drawing.Color{chart.ColorBlue, chart.ColorGreen, chart.ColorRed, chart.ColorAlternateGray, chart.ColorBlack, chart.ColorYellow, chart.ColorOrange}
	for i, k := range keys {
		ys := make([]float64, len(rows))
		for j, r := range rows {
			ys[j] = r.ErrorRateByHTTPProtocolPct[k]
			if ys[j] < 0 {
				ys[j] = math.NaN()
			}
		}
		st := pointStyle(palette[i%len(palette)])
		name := k
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
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	ch := chart.Chart{Title: "Error Rate by HTTP Protocol (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: &chart.ContinuousRange{Min: 0, Max: 100}, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Error percentage per protocol. Spikes may indicate protocol-specific issues.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderErrorShareByHTTPProtocolChart draws share of total errors by HTTP protocol.
func renderErrorShareByHTTPProtocolChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	keySet := map[string]struct{}{}
	for _, r := range rows {
		for k := range r.ErrorShareByHTTPProtocolPct {
			keySet[k] = struct{}{}
		}
	}
	if len(keySet) == 0 {
		cw, chh := chartSize(state)
		return drawWatermark(blank(cw, chh), "Situation: "+activeSituationLabel(state))
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	var series []chart.Series
	palette := []drawing.Color{chart.ColorBlue, chart.ColorGreen, chart.ColorRed, chart.ColorAlternateGray, chart.ColorBlack, chart.ColorYellow, chart.ColorOrange}
	for i, k := range keys {
		ys := make([]float64, len(rows))
		for j, r := range rows {
			ys[j] = r.ErrorShareByHTTPProtocolPct[k]
			if ys[j] < 0 {
				ys[j] = math.NaN()
			}
		}
		st := pointStyle(palette[i%len(palette)])
		name := k
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
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	ch := chart.Chart{Title: "Error Share by HTTP Protocol (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: &chart.ContinuousRange{Min: 0, Max: 100}, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Share of total errors per protocol. This typically sums to ~100% across visible protocols.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderPartialBodyRateByHTTPProtocolChart draws percentage of partial body requests by HTTP protocol.
func renderPartialBodyRateByHTTPProtocolChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	keySet := map[string]struct{}{}
	for _, r := range rows {
		for k := range r.PartialBodyRateByHTTPProtocolPct {
			keySet[k] = struct{}{}
		}
	}
	if len(keySet) == 0 {
		cw, chh := chartSize(state)
		return drawWatermark(blank(cw, chh), "Situation: "+activeSituationLabel(state))
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	var series []chart.Series
	palette := []drawing.Color{chart.ColorBlue, chart.ColorGreen, chart.ColorRed, chart.ColorAlternateGray, chart.ColorBlack, chart.ColorYellow, chart.ColorOrange}
	for i, k := range keys {
		ys := make([]float64, len(rows))
		for j, r := range rows {
			ys[j] = r.PartialBodyRateByHTTPProtocolPct[k]
			if ys[j] < 0 {
				ys[j] = math.NaN()
			}
		}
		st := pointStyle(palette[i%len(palette)])
		name := k
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
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	ch := chart.Chart{Title: "Partial Body Rate by HTTP Protocol (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: &chart.ContinuousRange{Min: 0, Max: 100}, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Percentage of incomplete (partial) responses per protocol.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

func renderTLSVersionMixChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	keySet := map[string]struct{}{}
	for _, r := range rows {
		for k := range r.TLSVersionRatePct {
			keySet[k] = struct{}{}
		}
	}
	if len(keySet) == 0 {
		cw, chh := chartSize(state)
		return drawWatermark(blank(cw, chh), "Situation: "+activeSituationLabel(state))
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	var series []chart.Series
	palette := []drawing.Color{chart.ColorBlue, chart.ColorGreen, chart.ColorRed, chart.ColorAlternateGray, chart.ColorBlack, chart.ColorYellow, chart.ColorOrange}
	for i, k := range keys {
		ys := make([]float64, len(rows))
		for j, r := range rows {
			ys[j] = r.TLSVersionRatePct[k]
			if ys[j] <= 0 {
				ys[j] = math.NaN()
			}
		}
		st := pointStyle(palette[i%len(palette)])
		name := k
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
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	ch := chart.Chart{Title: "TLS Version Mix (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: &chart.ContinuousRange{Min: 0, Max: 100}, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Distribution of negotiated TLS versions.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

func renderALPNMixChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	keySet := map[string]struct{}{}
	for _, r := range rows {
		for k := range r.ALPNRatePct {
			keySet[k] = struct{}{}
		}
	}
	if len(keySet) == 0 {
		cw, chh := chartSize(state)
		return drawWatermark(blank(cw, chh), "Situation: "+activeSituationLabel(state))
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	var series []chart.Series
	palette := []drawing.Color{chart.ColorBlue, chart.ColorGreen, chart.ColorRed, chart.ColorAlternateGray, chart.ColorBlack, chart.ColorYellow, chart.ColorOrange}
	for i, k := range keys {
		ys := make([]float64, len(rows))
		for j, r := range rows {
			ys[j] = r.ALPNRatePct[k]
			if ys[j] <= 0 {
				ys[j] = math.NaN()
			}
		}
		st := pointStyle(palette[i%len(palette)])
		name := k
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
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	ch := chart.Chart{Title: "ALPN Mix (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: &chart.ContinuousRange{Min: 0, Max: 100}, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Negotiated application protocols (ALPN). h2 indicates HTTP/2.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

func renderChunkedTransferRateChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	ys := make([]float64, len(rows))
	for i, r := range rows {
		ys[i] = r.ChunkedRatePct
	}
	st := pointStyle(chart.ColorBlue)
	var series chart.Series
	if timeMode {
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.TimeSeries{Name: "Chunked", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st}
		} else {
			series = chart.TimeSeries{Name: "Chunked", XValues: times, YValues: ys, Style: st}
		}
	} else {
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.ContinuousSeries{Name: "Chunked", XValues: []float64{xs[0], x2}, YValues: ys, Style: st}
		} else {
			series = chart.ContinuousSeries{Name: "Chunked", XValues: xs, YValues: ys, Style: st}
		}
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
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
	ch := chart.Chart{Title: "Chunked Transfer Rate (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: &chart.ContinuousRange{Min: 0, Max: 100}, Ticks: yTicks}, Series: []chart.Series{series}}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Percentage of responses using chunked transfer encoding.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderCoVChart draws AvgCoefVariationPct per batch (overall/IPv4/IPv6).
func renderCoVChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Coefficient of Variation (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: CoV shows relative variability (stddev/mean). Lower is steadier.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderPlateauCountChart plots AvgPlateauCount per batch.
func renderPlateauCountChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Plateau Count", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "count", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: Number of distinct speed plateaus per batch. Fewer can indicate steadier transfer.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderPlateauLongestChart plots AvgLongestPlateau (ms) per batch.
func renderPlateauLongestChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Longest Plateau (ms)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: Longest plateau duration in ms. Longer plateaus may indicate throttling or buffering.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderPlateauStableChart plots PlateauStableRatePct (percentage) per batch for overall/IPv4/IPv6.
func renderPlateauStableChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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
	var yAxisRange chart.Range
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
	ch := chart.Chart{Title: "Plateau Stable Rate (%)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
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
		img = drawHint(img, "Hint: Share of lines with stable speed plateau within batch. Higher is steadier.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderTailHeavinessChart plots AvgP99P50Ratio for speed (unitless ratio) per batch for overall/IPv4/IPv6.
func renderTailHeavinessChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
		return blank(w, h)
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
		add("Overall", func(b analysis.BatchSummary) float64 { return b.AvgP99P50Ratio }, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) float64 {
			if b.IPv4 == nil {
				return 0
			}
			return b.IPv4.AvgP99P50Ratio
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) float64 {
			if b.IPv6 == nil {
				return 0
			}
			return b.IPv6.AvgP99P50Ratio
		}, chart.ColorGreen)
	}
	var yAxisRange chart.Range
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if state.useRelative && haveY {
		if maxY <= minY {
			maxY = minY + 0.1
		}
		nMin, nMax := niceAxisBounds(minY, maxY)
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
	} else if !state.useRelative && haveY {
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
	ch := chart.Chart{Title: "Tail Heaviness (Speed P99/P50)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ratio", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Ratio of P99 to P50 speed. Higher means heavier tail/instability.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderFamilyDeltaSpeedChart plots IPv6−IPv4 AvgSpeed delta in selected unit.
func renderFamilyDeltaSpeedChart(state *uiState) image.Image {
	unitName, factor := speedUnitNameAndFactor(state.speedUnit)
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	ys := make([]float64, len(rows))
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	for i, r := range rows {
		if r.IPv4 == nil || r.IPv6 == nil {
			ys[i] = math.NaN()
			continue
		}
		v := (r.IPv6.AvgSpeed - r.IPv4.AvgSpeed) * factor
		ys[i] = v
		if v < minY {
			minY = v
		}
		if v > maxY {
			maxY = v
		}
	}
	st := pointStyle(chart.ColorRed)
	var series chart.Series
	if timeMode {
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.TimeSeries{Name: "IPv6−IPv4", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st}
		} else {
			series = chart.TimeSeries{Name: "IPv6−IPv4", XValues: times, YValues: ys, Style: st}
		}
	} else {
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.ContinuousSeries{Name: "IPv6−IPv4", XValues: []float64{xs[0], x2}, YValues: ys, Style: st}
		} else {
			series = chart.ContinuousSeries{Name: "IPv6−IPv4", XValues: xs, YValues: ys, Style: st}
		}
	}
	// Axis symmetric around 0 when absolute mode
	var yAxisRange chart.Range
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if haveY {
		nMin, nMax := niceAxisBounds(minY, maxY)
		if !state.useRelative {
			if nMin > 0 {
				nMin = 0
			}
			if nMax < 0 {
				nMax = 0
			}
		}
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
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
	ch := chart.Chart{Title: fmt.Sprintf("Family Delta – Speed (IPv6−IPv4) (%s)", unitName), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: unitName, Range: yAxisRange, Ticks: yTicks}, Series: []chart.Series{series}}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Positive delta means IPv6 faster than IPv4.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderFamilyDeltaTTFBChart plots (IPv4−IPv6) AvgTTFB delta in ms; positive means IPv6 lower/better.
func renderFamilyDeltaTTFBChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	ys := make([]float64, len(rows))
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	for i, r := range rows {
		if r.IPv4 == nil || r.IPv6 == nil {
			ys[i] = math.NaN()
			continue
		}
		v := (r.IPv4.AvgTTFB - r.IPv6.AvgTTFB)
		ys[i] = v
		if v < minY {
			minY = v
		}
		if v > maxY {
			maxY = v
		}
	}
	st := pointStyle(chart.ColorBlue)
	var series chart.Series
	if timeMode {
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.TimeSeries{Name: "IPv4−IPv6", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st}
		} else {
			series = chart.TimeSeries{Name: "IPv4−IPv6", XValues: times, YValues: ys, Style: st}
		}
	} else {
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.ContinuousSeries{Name: "IPv4−IPv6", XValues: []float64{xs[0], x2}, YValues: ys, Style: st}
		} else {
			series = chart.ContinuousSeries{Name: "IPv4−IPv6", XValues: xs, YValues: ys, Style: st}
		}
	}
	var yAxisRange chart.Range
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if haveY {
		nMin, nMax := niceAxisBounds(minY, maxY)
		if !state.useRelative {
			if nMin > 0 {
				nMin = 0
			}
			if nMax < 0 {
				nMax = 0
			}
		}
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
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
	ch := chart.Chart{Title: "Family Delta – TTFB (IPv4−IPv6) (ms)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "ms", Range: yAxisRange, Ticks: yTicks}, Series: []chart.Series{series}}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Positive delta means IPv6 has lower (better) TTFB.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderFamilyDeltaSpeedPctChart plots percent delta: (IPv6−IPv4)/IPv4 * 100
func renderFamilyDeltaSpeedPctChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	ys := make([]float64, len(rows))
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	for i, r := range rows {
		if r.IPv4 == nil || r.IPv6 == nil || r.IPv4.AvgSpeed == 0 {
			ys[i] = math.NaN()
			continue
		}
		v := (r.IPv6.AvgSpeed - r.IPv4.AvgSpeed) / r.IPv4.AvgSpeed * 100.0
		ys[i] = v
		if v < minY {
			minY = v
		}
		if v > maxY {
			maxY = v
		}
	}
	st := pointStyle(chart.ColorRed)
	var series chart.Series
	if timeMode {
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.TimeSeries{Name: "IPv6 vs IPv4 %", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st}
		} else {
			series = chart.TimeSeries{Name: "IPv6 vs IPv4 %", XValues: times, YValues: ys, Style: st}
		}
	} else {
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.ContinuousSeries{Name: "IPv6 vs IPv4 %", XValues: []float64{xs[0], x2}, YValues: ys, Style: st}
		} else {
			series = chart.ContinuousSeries{Name: "IPv6 vs IPv4 %", XValues: xs, YValues: ys, Style: st}
		}
	}
	var yAxisRange chart.Range
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if haveY {
		nMin, nMax := niceAxisBounds(minY, maxY)
		if !state.useRelative {
			if nMin > 0 {
				nMin = 0
			}
			if nMax < 0 {
				nMax = 0
			}
		}
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
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
	ch := chart.Chart{Title: "Family Delta – Speed % (IPv6 vs IPv4)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: []chart.Series{series}}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Positive % means IPv6 is faster vs IPv4.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderFamilyDeltaTTFBPctChart plots percent delta: (IPv4−IPv6)/IPv6 * 100 (positive = IPv6 lower/better latency)
func renderFamilyDeltaTTFBPctChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	ys := make([]float64, len(rows))
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	for i, r := range rows {
		if r.IPv4 == nil || r.IPv6 == nil || r.IPv6.AvgTTFB == 0 {
			ys[i] = math.NaN()
			continue
		}
		v := (r.IPv4.AvgTTFB - r.IPv6.AvgTTFB) / r.IPv6.AvgTTFB * 100.0
		ys[i] = v
		if v < minY {
			minY = v
		}
		if v > maxY {
			maxY = v
		}
	}
	st := pointStyle(chart.ColorBlue)
	var series chart.Series
	if timeMode {
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.TimeSeries{Name: "IPv6 vs IPv4 %", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st}
		} else {
			series = chart.TimeSeries{Name: "IPv6 vs IPv4 %", XValues: times, YValues: ys, Style: st}
		}
	} else {
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.ContinuousSeries{Name: "IPv6 vs IPv4 %", XValues: []float64{xs[0], x2}, YValues: ys, Style: st}
		} else {
			series = chart.ContinuousSeries{Name: "IPv6 vs IPv4 %", XValues: xs, YValues: ys, Style: st}
		}
	}
	var yAxisRange chart.Range
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if haveY {
		nMin, nMax := niceAxisBounds(minY, maxY)
		if !state.useRelative {
			if nMin > 0 {
				nMin = 0
			}
			if nMax < 0 {
				nMax = 0
			}
		}
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
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
	ch := chart.Chart{Title: "Family Delta – TTFB % (IPv6 vs IPv4)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: []chart.Series{series}}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Positive % means IPv6 has lower (better) TTFB.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderSLASpeedDeltaChart computes IPv6−IPv4 delta in percentage points using configured threshold
func renderSLASpeedDeltaChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	ys := make([]float64, len(rows))
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	for i, r := range rows {
		if r.IPv4 == nil || r.IPv6 == nil {
			ys[i] = math.NaN()
			continue
		}
		v4 := estimateCompliance(map[int]float64{50: r.IPv4.AvgP50Speed, 90: r.IPv4.AvgP90Speed, 95: r.IPv4.AvgP95Speed, 99: r.IPv4.AvgP99Speed}, float64(state.slaSpeedThresholdKbps), true)
		v6 := estimateCompliance(map[int]float64{50: r.IPv6.AvgP50Speed, 90: r.IPv6.AvgP90Speed, 95: r.IPv6.AvgP95Speed, 99: r.IPv6.AvgP99Speed}, float64(state.slaSpeedThresholdKbps), true)
		val := v6 - v4
		ys[i] = val
		if val < minY {
			minY = val
		}
		if val > maxY {
			maxY = val
		}
	}
	st := pointStyle(chart.ColorRed)
	var series chart.Series
	if timeMode {
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.TimeSeries{Name: "IPv6−IPv4 pp", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st}
		} else {
			series = chart.TimeSeries{Name: "IPv6−IPv4 pp", XValues: times, YValues: ys, Style: st}
		}
	} else {
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.ContinuousSeries{Name: "IPv6−IPv4 pp", XValues: []float64{xs[0], x2}, YValues: ys, Style: st}
		} else {
			series = chart.ContinuousSeries{Name: "IPv6−IPv4 pp", XValues: xs, YValues: ys, Style: st}
		}
	}
	var yAxisRange chart.Range
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if haveY {
		nMin, nMax := niceAxisBounds(minY, maxY)
		if !state.useRelative {
			if nMin > 0 {
				nMin = 0
			}
			if nMax < 0 {
				nMax = 0
			}
		}
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
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
	ch := chart.Chart{Title: "SLA Compliance Delta – Speed (pp)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "pp", Range: yAxisRange, Ticks: yTicks}, Series: []chart.Series{series}}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Positive pp means IPv6 has higher compliance vs IPv4.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderSLATTFBDeltaChart computes IPv6−IPv4 delta in percentage points using configured threshold
func renderSLATTFBDeltaChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	ys := make([]float64, len(rows))
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	for i, r := range rows {
		if r.IPv4 == nil || r.IPv6 == nil {
			ys[i] = math.NaN()
			continue
		}
		v4 := estimateCompliance(map[int]float64{50: r.IPv4.AvgP50TTFBMs, 90: r.IPv4.AvgP90TTFBMs, 95: r.IPv4.AvgP95TTFBMs, 99: r.IPv4.AvgP99TTFBMs}, float64(state.slaTTFBThresholdMs), false)
		v6 := estimateCompliance(map[int]float64{50: r.IPv6.AvgP50TTFBMs, 90: r.IPv6.AvgP90TTFBMs, 95: r.IPv6.AvgP95TTFBMs, 99: r.IPv6.AvgP99TTFBMs}, float64(state.slaTTFBThresholdMs), false)
		val := v6 - v4
		ys[i] = val
		if val < minY {
			minY = val
		}
		if val > maxY {
			maxY = val
		}
	}
	st := pointStyle(chart.ColorBlue)
	var series chart.Series
	if timeMode {
		if len(times) == 1 {
			t2 := times[0].Add(1 * time.Second)
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.TimeSeries{Name: "IPv6−IPv4 pp", XValues: []time.Time{times[0], t2}, YValues: ys, Style: st}
		} else {
			series = chart.TimeSeries{Name: "IPv6−IPv4 pp", XValues: times, YValues: ys, Style: st}
		}
	} else {
		if len(xs) == 1 {
			x2 := xs[0] + 1
			ys = append([]float64{ys[0]}, ys[0])
			series = chart.ContinuousSeries{Name: "IPv6−IPv4 pp", XValues: []float64{xs[0], x2}, YValues: ys, Style: st}
		} else {
			series = chart.ContinuousSeries{Name: "IPv6−IPv4 pp", XValues: xs, YValues: ys, Style: st}
		}
	}
	var yAxisRange chart.Range
	var yTicks []chart.Tick
	haveY := (minY != math.MaxFloat64 && maxY != -math.MaxFloat64)
	if haveY {
		nMin, nMax := niceAxisBounds(minY, maxY)
		if !state.useRelative {
			if nMin > 0 {
				nMin = 0
			}
			if nMax < 0 {
				nMax = 0
			}
		}
		yAxisRange = &chart.ContinuousRange{Min: nMin, Max: nMax}
		yTicks = niceTicks(nMin, nMax, 6)
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
	ch := chart.Chart{Title: "SLA Compliance Delta – TTFB (pp)", Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "pp", Range: yAxisRange, Ticks: yTicks}, Series: []chart.Series{series}}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Positive pp means IPv6 has higher compliance vs IPv4.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// SLA thresholds (configured via state)

// estimateCompliance returns approximate % of lines meeting threshold using available percentiles.
// For speed: threshold is minimum speed; for ttfb: maximum allowed latency.
func estimateCompliance(percentiles map[int]float64, threshold float64, greaterBetter bool) float64 {
	// consider 50, 90, 95, 99 percentiles if present
	type p struct {
		k int
		v float64
	}
	var ps []p
	for _, k := range []int{50, 90, 95, 99} {
		if v, ok := percentiles[k]; ok && v > 0 {
			ps = append(ps, p{k, v})
		}
	}
	if len(ps) == 0 {
		return math.NaN()
	}
	// choose highest percentile satisfying condition
	best := 0
	for _, e := range ps {
		if greaterBetter {
			if e.v >= threshold && e.k > best {
				best = e.k
			}
		} else {
			if e.v <= threshold && e.k > best {
				best = e.k
			}
		}
	}
	if best == 0 {
		// none satisfied; small value (e.g., 0 or 1)
		return 0
	}
	return float64(best)
}

// renderSLASpeedChart renders estimated compliance % for speed threshold using percentiles (Overall/IPv4/IPv6).
func renderSLASpeedChart(state *uiState) image.Image {
	unitName, factor := speedUnitNameAndFactor(state.speedUnit)
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	minY, maxY := 100.0, 0.0
	add := func(name string, get func(b analysis.BatchSummary) map[int]float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		for i, r := range rows {
			m := get(r)
			// computation uses kbps in summaries; threshold is stored in kbps
			val := estimateCompliance(m, float64(state.slaSpeedThresholdKbps), true)
			if math.IsNaN(val) {
				ys[i] = math.NaN()
			} else {
				ys[i] = val
			}
			if ys[i] < minY {
				minY = ys[i]
			}
			if ys[i] > maxY {
				maxY = ys[i]
			}
		}
		st := pointStyle(col)
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
		add("Overall", func(b analysis.BatchSummary) map[int]float64 {
			return map[int]float64{50: b.AvgP50Speed, 90: b.AvgP90Speed, 95: b.AvgP95Speed, 99: b.AvgP99Speed}
		}, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) map[int]float64 {
			if b.IPv4 == nil {
				return nil
			}
			return map[int]float64{50: b.IPv4.AvgP50Speed, 90: b.IPv4.AvgP90Speed, 95: b.IPv4.AvgP95Speed, 99: b.IPv4.AvgP99Speed}
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) map[int]float64 {
			if b.IPv6 == nil {
				return nil
			}
			return map[int]float64{50: b.IPv6.AvgP50Speed, 90: b.IPv6.AvgP90Speed, 95: b.IPv6.AvgP95Speed, 99: b.IPv6.AvgP99Speed}
		}, chart.ColorGreen)
	}
	// Axis 0..100
	yAxisRange := &chart.ContinuousRange{Min: 0, Max: 100}
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
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
	ch := chart.Chart{Title: fmt.Sprintf("SLA Compliance – Speed (≥ %.1f %s P50 est)", float64(state.slaSpeedThresholdKbps)*factor, unitName), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Approximated via percentiles. Bars reflect ≥ threshold percentile.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// renderSLATTFBChart renders estimated compliance % for TTFB threshold using percentiles (Overall/IPv4/IPv6).
func renderSLATTFBChart(state *uiState) image.Image {
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		cw, chh := chartSize(state)
		return blank(cw, chh)
	}
	timeMode, times, xs, xAxis := buildXAxis(rows, state.xAxisMode)
	series := []chart.Series{}
	add := func(name string, get func(b analysis.BatchSummary) map[int]float64, col drawing.Color) {
		ys := make([]float64, len(rows))
		for i, r := range rows {
			m := get(r)
			val := estimateCompliance(m, float64(state.slaTTFBThresholdMs), false)
			if math.IsNaN(val) {
				ys[i] = math.NaN()
			} else {
				ys[i] = val
			}
		}
		st := pointStyle(col)
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
		add("Overall", func(b analysis.BatchSummary) map[int]float64 {
			return map[int]float64{50: b.AvgP50TTFBMs, 90: b.AvgP90TTFBMs, 95: b.AvgP95TTFBMs, 99: b.AvgP99TTFBMs}
		}, chart.ColorAlternateGray)
	}
	if state.showIPv4 {
		add("IPv4", func(b analysis.BatchSummary) map[int]float64 {
			if b.IPv4 == nil {
				return nil
			}
			return map[int]float64{50: b.IPv4.AvgP50TTFBMs, 90: b.IPv4.AvgP90TTFBMs, 95: b.IPv4.AvgP95TTFBMs, 99: b.IPv4.AvgP99TTFBMs}
		}, chart.ColorBlue)
	}
	if state.showIPv6 {
		add("IPv6", func(b analysis.BatchSummary) map[int]float64 {
			if b.IPv6 == nil {
				return nil
			}
			return map[int]float64{50: b.IPv6.AvgP50TTFBMs, 90: b.IPv6.AvgP90TTFBMs, 95: b.IPv6.AvgP95TTFBMs, 99: b.IPv6.AvgP99TTFBMs}
		}, chart.ColorGreen)
	}
	yAxisRange := &chart.ContinuousRange{Min: 0, Max: 100}
	yTicks := []chart.Tick{{Value: 0, Label: "0"}, {Value: 25, Label: "25"}, {Value: 50, Label: "50"}, {Value: 75, Label: "75"}, {Value: 100, Label: "100"}}
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
	ch := chart.Chart{Title: fmt.Sprintf("SLA Compliance – TTFB (≤ %d ms P95 est)", state.slaTTFBThresholdMs), Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}}, XAxis: xAxis, YAxis: chart.YAxis{Name: "%", Range: yAxisRange, Ticks: yTicks}, Series: series}
	themeChart(&ch)
	cw, chh := chartSize(state)
	ch.Width, ch.Height = cw, chh
	ch.Elements = []chart.Renderable{chart.Legend(&ch)}
	var buf bytes.Buffer
	if err := ch.Render(chart.PNG, &buf); err != nil {
		return blank(cw, chh)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		return blank(cw, chh)
	}
	if state.showHints {
		img = drawHint(img, "Hint: Approximated via percentiles. Higher means more requests meet TTFB target.")
	}
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
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
	// Use same font approach as watermark (TTF if available; fallback to basicfont)
	var face font.Face
	if res := theme.DefaultTheme().Font(fyne.TextStyle{}); res != nil {
		if f, err := opentype.Parse(res.Content()); err == nil {
			if ff, err2 := opentype.NewFace(f, &opentype.FaceOptions{Size: 14, DPI: 96, Hinting: font.HintingFull}); err2 == nil {
				face = ff
			}
		}
	}
	if face == nil {
		face = basicfont.Face7x13
	}
	// Colors will be chosen dynamically after sampling background in target region
	var textCol, shadowCol, boxBG, boxBorder *image.Uniform
	// Measure text width/height using metrics
	drMeasure := &font.Drawer{Face: face}
	tw := drMeasure.MeasureString(text).Ceil()
	m := face.Metrics()
	asc := m.Ascent.Ceil()
	desc := m.Descent.Ceil()
	th := asc + desc
	if th <= 0 {
		th = 16
	}
	x := b.Min.X + 8
	yBase := b.Max.Y - 6
	// Choose colors. In Light mode use light text on a darker background for readability.
	if strings.EqualFold(screenshotThemeGlobal, "light") {
		textCol = image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 255})
		shadowCol = image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 220})
		boxBG = image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 220})
		boxBorder = image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 60})
	} else {
		// Dark theme: light text on dark box
		textCol = image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 255})
		shadowCol = image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 220})
		boxBG = image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 220})
		boxBorder = image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 60})
	}
	// Draw bordered background rectangle for readability
	rectOuter := image.Rect(x-pad, yBase-th-pad, x+tw+pad, yBase+pad/2)
	rectInner := image.Rect(rectOuter.Min.X+1, rectOuter.Min.Y+1, rectOuter.Max.X-1, rectOuter.Max.Y-1)
	draw.Draw(rgba, rectOuter, boxBorder, image.Point{}, draw.Over)
	draw.Draw(rgba, rectInner, boxBG, image.Point{}, draw.Over)
	// Draw subtle multi-directional shadow then text for improved contrast
	outline := [][2]int{{1, 1}, {-1, 1}, {1, -1}, {-1, -1}, {1, 0}, {-1, 0}, {0, 1}, {0, -1}}
	for _, d := range outline {
		drShadow := &font.Drawer{Dst: rgba, Src: shadowCol, Face: face, Dot: fixed.Point26_6{X: fixed.I(x + d[0]), Y: fixed.I(yBase - desc + d[1])}}
		drShadow.DrawString(text)
	}
	// Main text
	dr := &font.Drawer{Dst: rgba, Src: textCol, Face: face, Dot: fixed.Point26_6{X: fixed.I(x), Y: fixed.I(yBase - desc)}}
	dr.DrawString(text)
	return rgba
}

// drawWatermark draws a small bottom-right watermark with the given text.
func drawWatermark(img image.Image, text string) image.Image {
	if img == nil || strings.TrimSpace(text) == "" {
		return img
	}
	b := img.Bounds()
	rgba := image.NewRGBA(b)
	draw.Draw(rgba, b, img, b.Min, draw.Src)
	// styling
	pad := 6
	// Try to use a TTF face for better readability; fallback to basicfont if needed
	var face font.Face
	if res := theme.DefaultTheme().Font(fyne.TextStyle{}); res != nil {
		if f, err := opentype.Parse(res.Content()); err == nil {
			if ff, err2 := opentype.NewFace(f, &opentype.FaceOptions{Size: 14, DPI: 96, Hinting: font.HintingFull}); err2 == nil {
				face = ff
			}
		}
	}
	if face == nil {
		face = basicfont.Face7x13
	}
	// Colors picked dynamically based on underlying background region for robust contrast
	var textCol, shadowCol, boxBG, boxBorder *image.Uniform
	drMeasure := &font.Drawer{Face: face}
	tw := drMeasure.MeasureString(text).Ceil()
	m := face.Metrics()
	asc := m.Ascent.Ceil()
	desc := m.Descent.Ceil()
	th := asc + desc
	if th <= 0 {
		th = 16
	}
	// placement bottom-right
	x := b.Max.X - tw - 8
	yBase := b.Max.Y - 6
	// Pick colors: in Light mode use light text on darker background; Dark uses dark box + white text
	if strings.EqualFold(screenshotThemeGlobal, "light") {
		textCol = image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 255})
		shadowCol = image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 220})
		boxBG = image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 220})
		boxBorder = image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 60})
	} else {
		textCol = image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 255})
		shadowCol = image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 220})
		boxBG = image.NewUniform(color.RGBA{R: 0, G: 0, B: 0, A: 220})
		boxBorder = image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 60})
	}
	// background box with subtle border (theme- and content-aware)
	rectOuter := image.Rect(x-pad, yBase-th-pad, x+tw+pad, yBase+pad/2)
	rectInner := image.Rect(rectOuter.Min.X+1, rectOuter.Min.Y+1, rectOuter.Max.X-1, rectOuter.Max.Y-1)
	draw.Draw(rgba, rectOuter, boxBorder, image.Point{}, draw.Over)
	draw.Draw(rgba, rectInner, boxBG, image.Point{}, draw.Over)
	// outline shadows
	outline := [][2]int{{1, 1}, {-1, 1}, {1, -1}, {-1, -1}, {1, 0}, {-1, 0}, {0, 1}, {0, -1}}
	for _, dxy := range outline {
		dr := &font.Drawer{Dst: rgba, Src: shadowCol, Face: face, Dot: fixed.Point26_6{X: fixed.I(x + dxy[0]), Y: fixed.I(yBase - desc + dxy[1])}}
		dr.DrawString(text)
	}
	// main text
	dr := &font.Drawer{Dst: rgba, Src: textCol, Face: face, Dot: fixed.Point26_6{X: fixed.I(x), Y: fixed.I(yBase - desc)}}
	dr.DrawString(text)
	return rgba
}

// isRegionLight samples the average luminance of the given rectangle to determine if the region is light.
// (isRegionLight removed; overlays now use fixed high-contrast theme-specific colors)

// activeSituationLabel returns the visible label for the current situation (or "All").
func activeSituationLabel(state *uiState) string {
	if state == nil || strings.TrimSpace(state.situation) == "" || strings.EqualFold(state.situation, "All") {
		return "All"
	}
	return state.situation
}

// (titles intentionally do not include the situation; see watermark for context)

// drawCaption draws a small caption near the top-left of the image.
// (caption overlay removed for cleaner look)

// renderPercentilesChartWithFamily draws a compact percentiles chart for the given family (overall/ipv4/ipv6).
func renderPercentilesChartWithFamily(state *uiState, fam string) image.Image {
	unitName, factor := speedUnitNameAndFactor(state.speedUnit)
	rows := filteredSummaries(state)
	if len(rows) == 0 {
		w, h := chartSize(state)
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

	var yAxisRange chart.Range
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
		Title:      fmt.Sprintf("%sSpeed Percentiles (%s)", titlePrefix, unitName),
		Background: chart.Style{Padding: chart.Box{Top: 14, Left: 16, Right: 12, Bottom: padBottom}},
		XAxis:      xAxis,
		YAxis:      chart.YAxis{Name: unitName, Range: yAxisRange, Ticks: yTicks},
		Series:     series,
	}
	themeChart(&ch)
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
	return drawWatermark(img, "Situation: "+activeSituationLabel(state))
}

// compareChartSize returns a compact size for side-by-side percentiles charts
// (compareChartSize removed; all charts now use full-width chartSize for consistency)

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
	// subtle background, theme aware
	var bg color.RGBA
	if strings.EqualFold(screenshotThemeGlobal, "light") {
		bg = color.RGBA{R: 250, G: 250, B: 250, A: 255}
	} else {
		bg = color.RGBA{R: 18, G: 18, B: 18, A: 255}
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, bg)
		}
	}
	return img
}

// themeChart applies light/dark styling to chart backgrounds, axes, ticks, grids, and titles
// according to screenshotThemeGlobal. It does not change paddings or series colors.
func themeChart(ch *chart.Chart) {
	if ch == nil {
		return
	}
	var (
		bg, text, grid, axis drawing.Color
	)
	if strings.EqualFold(screenshotThemeGlobal, "light") {
		bg = drawing.ColorFromHex("FAFAFA")
		text = drawing.ColorFromHex("141414")
		grid = drawing.ColorFromHex("DDDDDD")
		axis = drawing.ColorFromHex("BBBBBB")
	} else {
		// dark
		bg = drawing.ColorFromHex("121212")
		text = drawing.ColorFromHex("F0F0F0")
		grid = drawing.ColorFromHex("333333")
		axis = drawing.ColorFromHex("666666")
	}
	// Backgrounds
	ch.Background.FillColor = bg
	ch.Canvas.FillColor = bg
	// Axes & ticks
	ch.XAxis.Style.FontColor = text
	ch.XAxis.Style.StrokeColor = axis
	ch.XAxis.TickStyle.FontColor = text
	// X major/minor grid
	ch.XAxis.GridMajorStyle.StrokeColor = grid
	ch.XAxis.GridMajorStyle.StrokeWidth = 1
	ch.XAxis.GridMinorStyle.StrokeColor = drawing.Color{R: grid.R, G: grid.G, B: grid.B, A: 110}
	ch.XAxis.GridMinorStyle.StrokeWidth = 1
	ch.XAxis.GridMinorStyle.StrokeDashArray = []float64{2, 3}
	ch.YAxis.Style.FontColor = text
	ch.YAxis.Style.StrokeColor = axis
	ch.YAxis.TickStyle.FontColor = text
	// Y major/minor grid
	ch.YAxis.GridMajorStyle.StrokeColor = grid
	ch.YAxis.GridMajorStyle.StrokeWidth = 1
	ch.YAxis.GridMinorStyle.StrokeColor = drawing.Color{R: grid.R, G: grid.G, B: grid.B, A: 110}
	ch.YAxis.GridMinorStyle.StrokeWidth = 1
	ch.YAxis.GridMinorStyle.StrokeDashArray = []float64{2, 3}
	// Title color
	ch.TitleStyle.FontColor = text
	// Best-effort legend theming: legend renders text using default style; set Title/Font colors to improve contrast.
	// Many charts add the legend via chart.Legend(&ch); ensure text contrasts by setting DefaultTextColor-like fields.
	// Note: go-chart does not expose a direct LegendStyle here; legend inherits canvas, so background is already themed.
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
	// Gather images in display order (match on-screen order)
	imgs := []image.Image{}
	labels := []string{}
	// Setup timings first
	if state.setupDNSImgCanvas != nil && state.setupDNSImgCanvas.Image != nil {
		imgs = append(imgs, state.setupDNSImgCanvas.Image)
		labels = append(labels, "DNS Lookup Time (ms)")
	}
	if state.setupConnImgCanvas != nil && state.setupConnImgCanvas.Image != nil {
		imgs = append(imgs, state.setupConnImgCanvas.Image)
		labels = append(labels, "TCP Connect Time (ms)")
	}
	if state.setupTLSImgCanvas != nil && state.setupTLSImgCanvas.Image != nil {
		imgs = append(imgs, state.setupTLSImgCanvas.Image)
		labels = append(labels, "TLS Handshake Time (ms)")
	}
	// Then averages and the rest
	// Transport/Protocol block (appears before Speed on-screen)
	if state.protocolMixImgCanvas != nil && state.protocolMixImgCanvas.Image != nil {
		imgs = append(imgs, state.protocolMixImgCanvas.Image)
		labels = append(labels, "HTTP Protocol Mix (%)")
	}
	if state.protocolAvgSpeedImgCanvas != nil && state.protocolAvgSpeedImgCanvas.Image != nil {
		imgs = append(imgs, state.protocolAvgSpeedImgCanvas.Image)
		labels = append(labels, "Avg Speed by HTTP Protocol")
	}
	if state.protocolStallRateImgCanvas != nil && state.protocolStallRateImgCanvas.Image != nil {
		imgs = append(imgs, state.protocolStallRateImgCanvas.Image)
		labels = append(labels, "Stall Rate by HTTP Protocol (%)")
	}
	if state.protocolPartialRateImgCanvas != nil && state.protocolPartialRateImgCanvas.Image != nil {
		imgs = append(imgs, state.protocolPartialRateImgCanvas.Image)
		labels = append(labels, "Partial Body Rate by HTTP Protocol (%)")
	}
	if state.protocolErrorRateImgCanvas != nil && state.protocolErrorRateImgCanvas.Image != nil {
		imgs = append(imgs, state.protocolErrorRateImgCanvas.Image)
		labels = append(labels, "Error Rate by HTTP Protocol (%)")
	}
	if state.protocolErrorShareImgCanvas != nil && state.protocolErrorShareImgCanvas.Image != nil {
		imgs = append(imgs, state.protocolErrorShareImgCanvas.Image)
		labels = append(labels, "Error Share by HTTP Protocol (%)")
	}
	if state.tlsVersionMixImgCanvas != nil && state.tlsVersionMixImgCanvas.Image != nil {
		imgs = append(imgs, state.tlsVersionMixImgCanvas.Image)
		labels = append(labels, "TLS Version Mix (%)")
	}
	if state.alpnMixImgCanvas != nil && state.alpnMixImgCanvas.Image != nil {
		imgs = append(imgs, state.alpnMixImgCanvas.Image)
		labels = append(labels, "ALPN Mix (%)")
	}
	if state.chunkedRateImgCanvas != nil && state.chunkedRateImgCanvas.Image != nil {
		imgs = append(imgs, state.chunkedRateImgCanvas.Image)
		labels = append(labels, "Chunked Transfer Rate (%)")
	}

	// Averages and remaining charts
	if state.speedImgCanvas != nil && state.speedImgCanvas.Image != nil {
		imgs = append(imgs, state.speedImgCanvas.Image)
		labels = append(labels, "Speed")
	}
	// Self-test baseline
	if state.selfTestImgCanvas != nil && state.selfTestImgCanvas.Image != nil {
		imgs = append(imgs, state.selfTestImgCanvas.Image)
		labels = append(labels, "Local Throughput Self-Test")
	}
	// Speed percentiles panels
	if state.pctlOverallImg != nil && state.pctlOverallImg.Visible() && state.pctlOverallImg.Image != nil {
		imgs = append(imgs, state.pctlOverallImg.Image)
		labels = append(labels, "Speed Percentiles – Overall")
	}
	if state.pctlIPv4Img != nil && state.pctlIPv4Img.Visible() && state.pctlIPv4Img.Image != nil {
		imgs = append(imgs, state.pctlIPv4Img.Image)
		labels = append(labels, "Speed Percentiles – IPv4")
	}
	if state.pctlIPv6Img != nil && state.pctlIPv6Img.Visible() && state.pctlIPv6Img.Image != nil {
		imgs = append(imgs, state.pctlIPv6Img.Image)
		labels = append(labels, "Speed Percentiles – IPv6")
	}
	// TTFB average
	if state.ttfbImgCanvas != nil && state.ttfbImgCanvas.Image != nil {
		imgs = append(imgs, state.ttfbImgCanvas.Image)
		labels = append(labels, "TTFB (Avg)")
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
	// New diagnostics in on-screen order
	if state.tailRatioImgCanvas != nil && state.tailRatioImgCanvas.Image != nil {
		imgs = append(imgs, state.tailRatioImgCanvas.Image)
		labels = append(labels, "Tail Heaviness (P99/P50 Speed)")
	}
	if state.ttfbTailRatioImgCanvas != nil && state.ttfbTailRatioImgCanvas.Image != nil {
		imgs = append(imgs, state.ttfbTailRatioImgCanvas.Image)
		labels = append(labels, "TTFB Tail Heaviness (P95/P50)")
	}
	if state.speedDeltaImgCanvas != nil && state.speedDeltaImgCanvas.Image != nil {
		imgs = append(imgs, state.speedDeltaImgCanvas.Image)
		labels = append(labels, "Family Delta – Speed (IPv6−IPv4)")
	}
	if state.ttfbDeltaImgCanvas != nil && state.ttfbDeltaImgCanvas.Image != nil {
		imgs = append(imgs, state.ttfbDeltaImgCanvas.Image)
		labels = append(labels, "Family Delta – TTFB (IPv4−IPv6)")
	}
	if state.speedDeltaPctImgCanvas != nil && state.speedDeltaPctImgCanvas.Image != nil {
		imgs = append(imgs, state.speedDeltaPctImgCanvas.Image)
		labels = append(labels, "Family Delta – Speed % (IPv6 vs IPv4)")
	}
	if state.ttfbDeltaPctImgCanvas != nil && state.ttfbDeltaPctImgCanvas.Image != nil {
		imgs = append(imgs, state.ttfbDeltaPctImgCanvas.Image)
		labels = append(labels, "Family Delta – TTFB % (IPv6 vs IPv4)")
	}
	if state.slaSpeedImgCanvas != nil && state.slaSpeedImgCanvas.Image != nil {
		imgs = append(imgs, state.slaSpeedImgCanvas.Image)
		labels = append(labels, "SLA Compliance – Speed")
	}
	if state.slaTTFBImgCanvas != nil && state.slaTTFBImgCanvas.Image != nil {
		imgs = append(imgs, state.slaTTFBImgCanvas.Image)
		labels = append(labels, "SLA Compliance – TTFB")
	}
	if state.slaSpeedDeltaImgCanvas != nil && state.slaSpeedDeltaImgCanvas.Image != nil {
		imgs = append(imgs, state.slaSpeedDeltaImgCanvas.Image)
		labels = append(labels, "SLA Compliance Delta – Speed (pp)")
	}
	if state.slaTTFBDeltaImgCanvas != nil && state.slaTTFBDeltaImgCanvas.Image != nil {
		imgs = append(imgs, state.slaTTFBDeltaImgCanvas.Image)
		labels = append(labels, "SLA Compliance Delta – TTFB (pp)")
	}
	// TTFB P95−P50 Gap
	if state.tpctlP95GapImgCanvas != nil && state.tpctlP95GapImgCanvas.Image != nil {
		imgs = append(imgs, state.tpctlP95GapImgCanvas.Image)
		labels = append(labels, "TTFB P95−P50 Gap")
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
	// Stability & quality
	if state.lowSpeedImgCanvas != nil && state.lowSpeedImgCanvas.Image != nil {
		imgs = append(imgs, state.lowSpeedImgCanvas.Image)
		labels = append(labels, "Low-Speed Time Share")
	}
	if state.stallRateImgCanvas != nil && state.stallRateImgCanvas.Image != nil {
		imgs = append(imgs, state.stallRateImgCanvas.Image)
		labels = append(labels, "Stall Rate")
	}
	if state.pretffbBlock != nil && state.pretffbBlock.Visible() && state.pretffbImgCanvas != nil && state.pretffbImgCanvas.Image != nil {
		imgs = append(imgs, state.pretffbImgCanvas.Image)
		labels = append(labels, "Pre‑TTFB Stall Rate")
	}
	if state.partialBodyImgCanvas != nil && state.partialBodyImgCanvas.Image != nil {
		imgs = append(imgs, state.partialBodyImgCanvas.Image)
		labels = append(labels, "Partial Body Rate")
	}
	if state.stallCountImgCanvas != nil && state.stallCountImgCanvas.Image != nil {
		imgs = append(imgs, state.stallCountImgCanvas.Image)
		labels = append(labels, "Stalled Requests Count")
	}
	if state.stallTimeImgCanvas != nil && state.stallTimeImgCanvas.Image != nil {
		imgs = append(imgs, state.stallTimeImgCanvas.Image)
		labels = append(labels, "Avg Stall Time")
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
	// Fill background to match theme
	var bg color.RGBA
	if strings.EqualFold(screenshotThemeGlobal, "light") {
		bg = color.RGBA{R: 250, G: 250, B: 250, A: 255}
	} else {
		bg = color.RGBA{R: 18, G: 18, B: 18, A: 255}
	}
	for y := 0; y < totalH; y++ {
		for x := 0; x < maxW; x++ {
			out.SetRGBA(x, y, bg)
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
	// Only persist lastSituation if we have a value; avoid wiping a previously saved value with empty during startup
	if strings.TrimSpace(state.situation) != "" {
		prefs.SetString("lastSituation", state.situation)
		fmt.Printf("[viewer] prefs save: lastSituation=%q\n", state.situation)
	}
	prefs.SetInt("batchesN", state.batchesN)
	prefs.SetBool("showOverall", state.showOverall)
	prefs.SetBool("showIPv4", state.showIPv4)
	prefs.SetBool("showIPv6", state.showIPv6)
	prefs.SetString("xAxisMode", state.xAxisMode)
	prefs.SetString("yScaleMode", state.yScaleMode)
	prefs.SetString("speedUnit", state.speedUnit)
	prefs.SetBool("crosshair", state.crosshairEnabled)
	prefs.SetBool("showHints", state.showHints)
	prefs.SetBool("showDNSLegacy", state.showDNSLegacy)
	// Pre‑TTFB chart visibility
	prefs.SetBool("showPreTTFB", state.showPreTTFB)
	// Pre‑TTFB auto-hide when all-zero
	prefs.SetBool("autoHidePreTTFB", state.autoHidePreTTFB)
	// SLA thresholds
	prefs.SetInt("slaSpeedThresholdKbps", state.slaSpeedThresholdKbps)
	prefs.SetInt("slaTTFBThresholdMs", state.slaTTFBThresholdMs)
	// Low-speed threshold
	prefs.SetInt("lowSpeedThresholdKbps", state.lowSpeedThresholdKbps)
	// Rolling overlays
	prefs.SetBool("showRolling", state.showRolling)
	prefs.SetBool("showRollingBand", state.showRollingBand)
	prefs.SetInt("rollingWindow", state.rollingWindow)
	// (removed: pctl prefs)
}

func loadPrefs(state *uiState, avg *widget.Check, v4 *widget.Check, v6 *widget.Check, fileLabel *widget.Label, tabs *container.AppTabs) {
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
	state.showPreTTFB = prefs.BoolWithFallback("showPreTTFB", state.showPreTTFB)
	state.autoHidePreTTFB = prefs.BoolWithFallback("autoHidePreTTFB", state.autoHidePreTTFB)
	if avg != nil {
		avg.SetChecked(state.showOverall)
	}
	if v4 != nil {
		v4.SetChecked(state.showIPv4)
	}
	if v6 != nil {
		v6.SetChecked(state.showIPv6)
	}
	// Load saved situation and normalize whitespace
	rawSit := strings.TrimSpace(prefs.StringWithFallback("lastSituation", state.situation))
	if strings.EqualFold(rawSit, "all") {
		state.situation = "All"
	} else {
		state.situation = rawSit
	}
	if state.situation == "" || strings.EqualFold(state.situation, "All") {
		fmt.Printf("[viewer] prefs: lastSituation=<All>\n")
	} else {
		fmt.Printf("[viewer] prefs: lastSituation=%q\n", state.situation)
	}
	mode := prefs.StringWithFallback("xAxisMode", state.xAxisMode)
	switch mode {
	case "batch", "run_tag", "time":
		state.xAxisMode = mode
	}
	ymode := prefs.StringWithFallback("yScaleMode", state.yScaleMode)
	switch ymode {
	case "absolute", "relative":
		state.yScaleMode = ymode
	}
	state.useRelative = strings.EqualFold(state.yScaleMode, "relative")
	if su := prefs.StringWithFallback("speedUnit", state.speedUnit); su != "" {
		state.speedUnit = su
	}
	state.crosshairEnabled = prefs.BoolWithFallback("crosshair", state.crosshairEnabled)
	if tabs != nil {
		idx := prefs.IntWithFallback("selectedTabIndex", 0)
		if idx >= 0 && idx < len(tabs.Items) {
			tabs.SelectIndex(idx)
		}
	}
	state.showHints = prefs.BoolWithFallback("showHints", state.showHints)
	state.showDNSLegacy = prefs.BoolWithFallback("showDNSLegacy", state.showDNSLegacy)
	// SLA thresholds (persisted)
	if v := prefs.IntWithFallback("slaSpeedThresholdKbps", state.slaSpeedThresholdKbps); v > 0 {
		state.slaSpeedThresholdKbps = v
	}
	if v := prefs.IntWithFallback("slaTTFBThresholdMs", state.slaTTFBThresholdMs); v > 0 {
		state.slaTTFBThresholdMs = v
	}
	// Low-speed threshold
	if v := prefs.IntWithFallback("lowSpeedThresholdKbps", state.lowSpeedThresholdKbps); v > 0 {
		state.lowSpeedThresholdKbps = v
	}
	// Rolling overlays
	state.showRolling = prefs.BoolWithFallback("showRolling", state.showRolling)
	state.showRollingBand = prefs.BoolWithFallback("showRollingBand", state.showRollingBand)
	if v := prefs.IntWithFallback("rollingWindow", state.rollingWindow); v > 0 {
		state.rollingWindow = v
	}
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
	mode     string // "speed", "ttfb", "error", "jitter", "cov", "pctl_overall", "pctl_ipv4", "pctl_ipv6", ...
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
		case "low_speed_share":
			imgCanvas = r.c.state.lowSpeedImgCanvas
		case "stall_rate":
			imgCanvas = r.c.state.stallRateImgCanvas
		case "pretffb_stall_rate":
			imgCanvas = r.c.state.pretffbImgCanvas
		case "stall_time":
			imgCanvas = r.c.state.stallTimeImgCanvas
		case "stall_count":
			imgCanvas = r.c.state.stallCountImgCanvas
		case "tail_ratio":
			imgCanvas = r.c.state.tailRatioImgCanvas
		case "ttfb_tail_ratio":
			imgCanvas = r.c.state.ttfbTailRatioImgCanvas
		case "speed_delta_pct":
			imgCanvas = r.c.state.speedDeltaPctImgCanvas
		case "ttfb_delta_pct":
			imgCanvas = r.c.state.ttfbDeltaPctImgCanvas
		case "sla_speed_delta":
			imgCanvas = r.c.state.slaSpeedDeltaImgCanvas
		case "sla_ttfb_delta":
			imgCanvas = r.c.state.slaTTFBDeltaImgCanvas
		case "speed_delta":
			imgCanvas = r.c.state.speedDeltaImgCanvas
		case "ttfb_delta":
			imgCanvas = r.c.state.ttfbDeltaImgCanvas
		case "sla_speed":
			imgCanvas = r.c.state.slaSpeedImgCanvas
		case "sla_ttfb":
			imgCanvas = r.c.state.slaTTFBImgCanvas
		case "ttfb_p95_gap":
			imgCanvas = r.c.state.tpctlP95GapImgCanvas
		case "setup_dns":
			imgCanvas = r.c.state.setupDNSImgCanvas
		case "setup_conn":
			imgCanvas = r.c.state.setupConnImgCanvas
		case "setup_tls":
			imgCanvas = r.c.state.setupTLSImgCanvas
		case "protocol_mix":
			imgCanvas = r.c.state.protocolMixImgCanvas
		case "protocol_avg_speed":
			imgCanvas = r.c.state.protocolAvgSpeedImgCanvas
		case "protocol_stall_rate":
			imgCanvas = r.c.state.protocolStallRateImgCanvas
		case "protocol_error_rate":
			imgCanvas = r.c.state.protocolErrorRateImgCanvas
		case "tls_version_mix":
			imgCanvas = r.c.state.tlsVersionMixImgCanvas
		case "alpn_mix":
			imgCanvas = r.c.state.alpnMixImgCanvas
		case "chunked_rate":
			imgCanvas = r.c.state.chunkedRateImgCanvas
		case "selftest_speed":
			imgCanvas = r.c.state.selfTestImgCanvas
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
		case "low_speed_share":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", bs.LowSpeedTimeSharePct))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", bs.IPv4.LowSpeedTimeSharePct))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", bs.IPv6.LowSpeedTimeSharePct))
			}
		case "stall_rate":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f%%", bs.StallRatePct))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f%%", bs.IPv4.StallRatePct))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f%%", bs.IPv6.StallRatePct))
			}
		case "stall_time":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.0f ms", bs.AvgStallElapsedMs))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.0f ms", bs.IPv4.AvgStallElapsedMs))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.0f ms", bs.IPv6.AvgStallElapsedMs))
			}
		case "stall_count":
			if r.c.state.showOverall && bs.Lines > 0 && bs.StallRatePct > 0 {
				val := int(math.Round(float64(bs.Lines) * bs.StallRatePct / 100.0))
				lines = append(lines, fmt.Sprintf("Overall: %d", val))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil && bs.IPv4.Lines > 0 && bs.IPv4.StallRatePct > 0 {
				val := int(math.Round(float64(bs.IPv4.Lines) * bs.IPv4.StallRatePct / 100.0))
				lines = append(lines, fmt.Sprintf("IPv4: %d", val))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil && bs.IPv6.Lines > 0 && bs.IPv6.StallRatePct > 0 {
				val := int(math.Round(float64(bs.IPv6.Lines) * bs.IPv6.StallRatePct / 100.0))
				lines = append(lines, fmt.Sprintf("IPv6: %d", val))
			}
		case "tail_ratio":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.2f", bs.AvgP99P50Ratio))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f", bs.IPv4.AvgP99P50Ratio))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f", bs.IPv6.AvgP99P50Ratio))
			}
		case "speed_delta":
			unit, factor := speedUnitNameAndFactor(r.c.state.speedUnit)
			if bs.IPv4 != nil && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6−IPv4: %.2f %s", (bs.IPv6.AvgSpeed-bs.IPv4.AvgSpeed)*factor, unit))
			} else {
				lines = append(lines, "Insufficient family data")
			}
		case "ttfb_delta":
			if bs.IPv4 != nil && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv4−IPv6: %.0f ms", (bs.IPv4.AvgTTFB-bs.IPv6.AvgTTFB)))
			} else {
				lines = append(lines, "Insufficient family data")
			}
		case "sla_speed":
			// Estimate via percentiles
			get := func(b analysis.BatchSummary) map[int]float64 {
				return map[int]float64{50: b.AvgP50Speed, 90: b.AvgP90Speed, 95: b.AvgP95Speed, 99: b.AvgP99Speed}
			}
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.0f%%", estimateCompliance(get(bs), float64(r.c.state.slaSpeedThresholdKbps), true)))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.0f%%", estimateCompliance(map[int]float64{50: bs.IPv4.AvgP50Speed, 90: bs.IPv4.AvgP90Speed, 95: bs.IPv4.AvgP95Speed, 99: bs.IPv4.AvgP99Speed}, float64(r.c.state.slaSpeedThresholdKbps), true)))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.0f%%", estimateCompliance(map[int]float64{50: bs.IPv6.AvgP50Speed, 90: bs.IPv6.AvgP90Speed, 95: bs.IPv6.AvgP95Speed, 99: bs.IPv6.AvgP99Speed}, float64(r.c.state.slaSpeedThresholdKbps), true)))
			}
		case "sla_ttfb":
			get := func(b analysis.BatchSummary) map[int]float64 {
				return map[int]float64{50: b.AvgP50TTFBMs, 90: b.AvgP90TTFBMs, 95: b.AvgP95TTFBMs, 99: b.AvgP99TTFBMs}
			}
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.0f%%", estimateCompliance(get(bs), float64(r.c.state.slaTTFBThresholdMs), false)))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.0f%%", estimateCompliance(map[int]float64{50: bs.IPv4.AvgP50TTFBMs, 90: bs.IPv4.AvgP90TTFBMs, 95: bs.IPv4.AvgP95TTFBMs, 99: bs.IPv4.AvgP99TTFBMs}, float64(r.c.state.slaTTFBThresholdMs), false)))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.0f%%", estimateCompliance(map[int]float64{50: bs.IPv6.AvgP50TTFBMs, 90: bs.IPv6.AvgP90TTFBMs, 95: bs.IPv6.AvgP95TTFBMs, 99: bs.IPv6.AvgP99TTFBMs}, float64(r.c.state.slaTTFBThresholdMs), false)))
			}
		case "ttfb_p95_gap":
			if r.c.state.showOverall {
				gap := math.Max(0, bs.AvgP95TTFBMs-bs.AvgP50TTFBMs)
				if !math.IsNaN(gap) {
					lines = append(lines, fmt.Sprintf("Overall: %.0f ms", gap))
				}
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				gap := math.Max(0, bs.IPv4.AvgP95TTFBMs-bs.IPv4.AvgP50TTFBMs)
				if !math.IsNaN(gap) {
					lines = append(lines, fmt.Sprintf("IPv4: %.0f ms", gap))
				}
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				gap := math.Max(0, bs.IPv6.AvgP95TTFBMs-bs.IPv6.AvgP50TTFBMs)
				if !math.IsNaN(gap) {
					lines = append(lines, fmt.Sprintf("IPv6: %.0f ms", gap))
				}
			}
		case "ttfb_tail_ratio":
			if r.c.state.showOverall && bs.AvgP50TTFBMs > 0 {
				lines = append(lines, fmt.Sprintf("Overall: %.2f", bs.AvgP95TTFBMs/bs.AvgP50TTFBMs))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil && bs.IPv4.AvgP50TTFBMs > 0 {
				lines = append(lines, fmt.Sprintf("IPv4: %.2f", bs.IPv4.AvgP95TTFBMs/bs.IPv4.AvgP50TTFBMs))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil && bs.IPv6.AvgP50TTFBMs > 0 {
				lines = append(lines, fmt.Sprintf("IPv6: %.2f", bs.IPv6.AvgP95TTFBMs/bs.IPv6.AvgP50TTFBMs))
			}
		case "speed_delta_pct":
			if bs.IPv4 != nil && bs.IPv6 != nil && bs.IPv4.AvgSpeed > 0 {
				pct := (bs.IPv6.AvgSpeed - bs.IPv4.AvgSpeed) / bs.IPv4.AvgSpeed * 100
				lines = append(lines, fmt.Sprintf("IPv6 vs IPv4: %.1f%%", pct))
			} else {
				lines = append(lines, "Insufficient family data")
			}
		case "ttfb_delta_pct":
			if bs.IPv4 != nil && bs.IPv6 != nil && bs.IPv6.AvgTTFB > 0 {
				pct := (bs.IPv4.AvgTTFB - bs.IPv6.AvgTTFB) / bs.IPv6.AvgTTFB * 100
				lines = append(lines, fmt.Sprintf("IPv6 vs IPv4: %.1f%%", pct))
			} else {
				lines = append(lines, "Insufficient family data")
			}
		case "sla_speed_delta":
			if bs.IPv4 != nil && bs.IPv6 != nil {
				v4 := estimateCompliance(map[int]float64{50: bs.IPv4.AvgP50Speed, 90: bs.IPv4.AvgP90Speed, 95: bs.IPv4.AvgP95Speed, 99: bs.IPv4.AvgP99Speed}, float64(r.c.state.slaSpeedThresholdKbps), true)
				v6 := estimateCompliance(map[int]float64{50: bs.IPv6.AvgP50Speed, 90: bs.IPv6.AvgP90Speed, 95: bs.IPv6.AvgP95Speed, 99: bs.IPv6.AvgP99Speed}, float64(r.c.state.slaSpeedThresholdKbps), true)
				lines = append(lines, fmt.Sprintf("IPv6−IPv4: %.0f pp", v6-v4))
			} else {
				lines = append(lines, "Insufficient family data")
			}
		case "sla_ttfb_delta":
			if bs.IPv4 != nil && bs.IPv6 != nil {
				v4 := estimateCompliance(map[int]float64{50: bs.IPv4.AvgP50TTFBMs, 90: bs.IPv4.AvgP90TTFBMs, 95: bs.IPv4.AvgP95TTFBMs, 99: bs.IPv4.AvgP99TTFBMs}, float64(r.c.state.slaTTFBThresholdMs), false)
				v6 := estimateCompliance(map[int]float64{50: bs.IPv6.AvgP50TTFBMs, 90: bs.IPv6.AvgP90TTFBMs, 95: bs.IPv6.AvgP95TTFBMs, 99: bs.IPv6.AvgP99TTFBMs}, float64(r.c.state.slaTTFBThresholdMs), false)
				lines = append(lines, fmt.Sprintf("IPv6−IPv4: %.0f pp", v6-v4))
			} else {
				lines = append(lines, "Insufficient family data")
			}
		case "setup_dns":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.0f ms", bs.AvgDNSMs))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.0f ms", bs.IPv4.AvgDNSMs))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.0f ms", bs.IPv6.AvgDNSMs))
			}
		case "setup_conn":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.0f ms", bs.AvgConnectMs))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.0f ms", bs.IPv4.AvgConnectMs))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.0f ms", bs.IPv6.AvgConnectMs))
			}
		case "setup_tls":
			if r.c.state.showOverall {
				lines = append(lines, fmt.Sprintf("Overall: %.0f ms", bs.AvgTLSHandshake))
			}
			if r.c.state.showIPv4 && bs.IPv4 != nil {
				lines = append(lines, fmt.Sprintf("IPv4: %.0f ms", bs.IPv4.AvgTLSHandshake))
			}
			if r.c.state.showIPv6 && bs.IPv6 != nil {
				lines = append(lines, fmt.Sprintf("IPv6: %.0f ms", bs.IPv6.AvgTLSHandshake))
			}
		case "protocol_mix":
			if len(bs.HTTPProtocolRatePct) == 0 {
				lines = append(lines, "No protocol data")
				break
			}
			// stable order
			keys := make([]string, 0, len(bs.HTTPProtocolRatePct))
			for k := range bs.HTTPProtocolRatePct {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := bs.HTTPProtocolRatePct[k]
				lines = append(lines, fmt.Sprintf("%s: %.1f%%", k, v))
			}
		case "protocol_avg_speed":
			if len(bs.AvgSpeedByHTTPProtocolKbps) == 0 {
				lines = append(lines, "No protocol data")
				break
			}
			unit, factor := speedUnitNameAndFactor(r.c.state.speedUnit)
			keys := make([]string, 0, len(bs.AvgSpeedByHTTPProtocolKbps))
			for k := range bs.AvgSpeedByHTTPProtocolKbps {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := bs.AvgSpeedByHTTPProtocolKbps[k] * factor
				if v > 0 {
					lines = append(lines, fmt.Sprintf("%s: %.1f %s", k, v, unit))
				}
			}
		case "protocol_stall_rate":
			if len(bs.StallRateByHTTPProtocolPct) == 0 {
				lines = append(lines, "No protocol data")
				break
			}
			keys := make([]string, 0, len(bs.StallRateByHTTPProtocolPct))
			for k := range bs.StallRateByHTTPProtocolPct {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				lines = append(lines, fmt.Sprintf("%s: %.1f%%", k, bs.StallRateByHTTPProtocolPct[k]))
			}
		case "protocol_error_rate":
			if len(bs.ErrorRateByHTTPProtocolPct) == 0 {
				lines = append(lines, "No protocol data")
				break
			}
			keys := make([]string, 0, len(bs.ErrorRateByHTTPProtocolPct))
			for k := range bs.ErrorRateByHTTPProtocolPct {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				lines = append(lines, fmt.Sprintf("%s: %.1f%%", k, bs.ErrorRateByHTTPProtocolPct[k]))
			}
		case "tls_version_mix":
			if len(bs.TLSVersionRatePct) == 0 {
				lines = append(lines, "No TLS data")
				break
			}
			keys := make([]string, 0, len(bs.TLSVersionRatePct))
			for k := range bs.TLSVersionRatePct {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				lines = append(lines, fmt.Sprintf("%s: %.1f%%", k, bs.TLSVersionRatePct[k]))
			}
		case "alpn_mix":
			if len(bs.ALPNRatePct) == 0 {
				lines = append(lines, "No ALPN data")
				break
			}
			keys := make([]string, 0, len(bs.ALPNRatePct))
			for k := range bs.ALPNRatePct {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				lines = append(lines, fmt.Sprintf("%s: %.1f%%", k, bs.ALPNRatePct[k]))
			}
		case "chunked_rate":
			lines = append(lines, fmt.Sprintf("Chunked: %.1f%%", bs.ChunkedRatePct))
		case "selftest_speed":
			unit, factor := speedUnitNameAndFactor(r.c.state.speedUnit)
			if bs.LocalSelfTestKbps > 0 {
				lines = append(lines, fmt.Sprintf("Baseline: %.1f %s", bs.LocalSelfTestKbps*factor, unit))
			} else {
				lines = append(lines, "Baseline: n/a")
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
