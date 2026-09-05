//go:build windows

package main

import (
	"fmt"
	"math"
	"strings"
	"syscall"
	"unsafe"
)

// =====================================================================
// GDI+ flat API bindings — replaces Direct2D with a simpler C-style API
// from gdiplus.dll (system DLL, available since Windows XP).
// No COM vtables — every function is a regular DLL export.
// =====================================================================

var (
	gdiplusDLL = syscall.NewLazyDLL("gdiplus.dll")

	gdipStartup           = gdiplusDLL.NewProc("GdiplusStartup")
	gdipShutdown          = gdiplusDLL.NewProc("GdiplusShutdown")
	gdipCreateFromHWND    = gdiplusDLL.NewProc("GdipCreateFromHWND")
	gdipDeleteGraphics    = gdiplusDLL.NewProc("GdipDeleteGraphics")
	gdipSetSmoothingMode  = gdiplusDLL.NewProc("GdipSetSmoothingMode")
	gdipSetTextRendering  = gdiplusDLL.NewProc("GdipSetTextRenderingHint")
	gdipGraphicsClear     = gdiplusDLL.NewProc("GdipGraphicsClear")
	gdipCreateSolidFill   = gdiplusDLL.NewProc("GdipCreateSolidFill")
	gdipDeleteBrush       = gdiplusDLL.NewProc("GdipDeleteBrush")
	gdipSetSolidFillColor = gdiplusDLL.NewProc("GdipSetSolidFillColor")
	gdipCreatePen2        = gdiplusDLL.NewProc("GdipCreatePen2")
	gdipDeletePen         = gdiplusDLL.NewProc("GdipDeletePen")
	gdipDrawLine          = gdiplusDLL.NewProc("GdipDrawLine")
	gdipCreatePath        = gdiplusDLL.NewProc("GdipCreatePath")
	gdipDeletePath        = gdiplusDLL.NewProc("GdipDeletePath")
	gdipAddPathArc        = gdiplusDLL.NewProc("GdipAddPathArc")
	gdipAddPathLine       = gdiplusDLL.NewProc("GdipAddPathLine")
	gdipClosePathFigure   = gdiplusDLL.NewProc("GdipClosePathFigure")
	gdipFillPath          = gdiplusDLL.NewProc("GdipFillPath")
	gdipDrawPath          = gdiplusDLL.NewProc("GdipDrawPath")
	gdipCreateFont        = gdiplusDLL.NewProc("GdipCreateFont")
	gdipDeleteFont        = gdiplusDLL.NewProc("GdipDeleteFont")
	gdipCreateFontFamily  = gdiplusDLL.NewProc("GdipCreateFontFamilyFromName")
	gdipDeleteFontFamily  = gdiplusDLL.NewProc("GdipDeleteFontFamily")
	gdipCreateStringFmt   = gdiplusDLL.NewProc("GdipCreateStringFormat")
	gdipDeleteStringFmt   = gdiplusDLL.NewProc("GdipDeleteStringFormat")
	gdipSetStringFmtAlign = gdiplusDLL.NewProc("GdipSetStringFormatAlign")
	gdipSetStringFmtLine  = gdiplusDLL.NewProc("GdipSetStringFormatLineAlign")
	gdipStringFmtGenericTypographic = gdiplusDLL.NewProc("GdipStringFormatGetGenericTypographic")
	gdipDrawString        = gdiplusDLL.NewProc("GdipDrawString")
	gdipSetClipRect       = gdiplusDLL.NewProc("GdipSetClipRect")
	gdipResetClip         = gdiplusDLL.NewProc("GdipResetClip")
	gdipCreateFromHDC     = gdiplusDLL.NewProc("GdipCreateFromHDC")
	gdipGetDC             = gdiplusDLL.NewProc("GdipGetHDC")
	gdipReleaseDC         = gdiplusDLL.NewProc("GdipReleaseHDC")

	procInvalidateRect     = user32.NewProc("InvalidateRect")
	gdi32                  = syscall.NewLazyDLL("gdi32.dll")
	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procSelectObject       = gdi32.NewProc("SelectObject")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procDeleteDC           = gdi32.NewProc("DeleteDC")
	procBitBlt             = gdi32.NewProc("BitBlt")
	procSetPixel           = gdi32.NewProc("SetPixel")
	procExcludeClipRect    = gdi32.NewProc("ExcludeClipRect")
	procGetDC              = user32.NewProc("GetDC")
	procReleaseDC          = user32.NewProc("ReleaseDC")
	procCreateIconIndirect = user32.NewProc("CreateIconIndirect")
	procSendMessageW       = user32.NewProc("SendMessageW")
	procLoadIconW          = user32.NewProc("LoadIconW")
	gdipMeasureStr         = gdiplusDLL.NewProc("GdipMeasureString")
)

// GDI bitmap info for double-buffering
type bitmapInfoHeader struct {
	Size         uint32
	Width        int32
	Height       int32
	Planes       uint16
	BitCount     uint16
	Compression  uint32
	SizeImage    uint32
	XPelsPerM    int32
	YPelsPerM    int32
	ClrUsed      uint32
	ClrImportant uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
}

const (
	biRgb        = 0
	dibRgbColors = 0
	srccopy      = 0x00CC0020
)

// GDI+ constants
const (
	gpOk = 0

	gpUnitPixel = 2

	gpSmoothingAntiAlias = 4
	gpSmoothingNone      = 3

	gpTextRenderClearType = 5

	gpFillModeAlternate = 0

	gpStringAlignCenter = 1
	gpStringAlignNear   = 0

	gpLineAlignCenter = 1
	gpLineAlignNear   = 0

	wmSetIcon = 0x0080
	iconBig   = 1
	iconSmall = 0
	idcShield = 32518
)

// ARGB color helpers
func argb(r, g, b, a uint8) uint32 {
	return uint32(a)<<24 | uint32(r)<<16 | uint32(g)<<8 | uint32(b)
}

func argbFromColor(c d2dColorF) uint32 {
	return argb(
		uint8(c.R*255+0.5),
		uint8(c.G*255+0.5),
		uint8(c.B*255+0.5),
		uint8(c.A*255+0.5),
	)
}

// f32 converts a float32 to uintptr for GDI+ syscall arguments
func f32(v float32) uintptr {
	return uintptr(math.Float32bits(v))
}

// GDI+ startup input struct
type gdiplusStartupInput struct {
	Version          uint32
	Callback         uintptr
	SuppressBgThread int32
	SuppressExtCodec int32
}

// D2D helper structs (kept for compatibility with ui_windows.go)
type d2dColorF struct {
	R, G, B, A float32
}

type d2dPoint2F struct {
	X, Y float32
}

type d2dSizeU struct {
	Width, Height uint32
}

type d2dRectF struct {
	Left, Top, Right, Bottom float32
}

type d2dRoundedRect struct {
	Rect    d2dRectF
	RadiusX float32
	RadiusY float32
}

// Color helpers
func colorFromRGB(r, g, b uint8) d2dColorF {
	return d2dColorF{float32(r) / 255.0, float32(g) / 255.0, float32(b) / 255.0, 1.0}
}

func colorFromRGBA(r, g, b, a uint8) d2dColorF {
	return d2dColorF{float32(r) / 255.0, float32(g) / 255.0, float32(b) / 255.0, float32(a) / 255.0}
}

// Theme colors
var (
	colorBg       = colorFromRGB(0xF3, 0xF3, 0xF3)
	colorCard     = colorFromRGB(0xFF, 0xFF, 0xFF)
	colorPrimary  = colorFromRGB(0x00, 0x78, 0xD4)
	colorHover    = colorFromRGB(0x10, 0x6E, 0xBE)
	colorPress    = colorFromRGB(0x00, 0x5A, 0x9E)
	colorText     = colorFromRGB(0x1A, 0x1A, 0x1A)
	colorTextSec  = colorFromRGB(0x66, 0x66, 0x66)
	colorBorder   = colorFromRGB(0xE0, 0xE0, 0xE0)
	colorSuccess  = colorFromRGB(0x10, 0x7C, 0x10)
	colorError    = colorFromRGB(0xD1, 0x34, 0x38)
	colorInputBg  = colorFromRGB(0xFF, 0xFF, 0xFF)
	colorDisabled = colorFromRGB(0xCC, 0xCC, 0xCC)
	colorShadow   = colorFromRGBA(0, 0, 0, 30)
)

// gdiplusToken is set by GdiplusStartup
var gdiplusToken uintptr

// d2dResources holds all GDI+ drawing resources.
// Name kept for compatibility — internally uses GDI+ flat API.
type d2dResources struct {
	hwnd   uintptr
	width  int32
	height int32
	gfx    uintptr // current GpGraphics* (only valid between beginDraw/endDraw)

	// Double-buffering state
	memDC    uintptr // persistent memory DC
	memBmp   uintptr // current DIB section
	oldBmp   uintptr // original DC bitmap (for cleanup)
	paintHDC uintptr // set by caller before beginDraw

	// Pre-created brushes (GpSolidFill*)
	brushBg       uintptr
	brushCard     uintptr
	brushPrimary  uintptr
	brushHover    uintptr
	brushPress    uintptr
	brushText     uintptr
	brushTextSec  uintptr
	brushBorder   uintptr
	brushSuccess  uintptr
	brushError    uintptr
	brushInputBg  uintptr
	brushDisabled uintptr
	brushShadow   uintptr
	brushWhite    uintptr

	// Fonts (GpFont*)
	fmtTitle    uintptr
	fmtBody     uintptr
	fmtBodyBold uintptr
	fmtSmall    uintptr
	fmtMono     uintptr
	fmtBtn      uintptr
	fmtLabel    uintptr

	// String format for centered text (buttons)
	fmtCenter uintptr
	// String format for left-aligned text (default)
	fmtLeft uintptr
	// String format for top-left aligned text (multi-line areas)
	fmtTopLeft uintptr
	// String format for accurate text measurement (no padding)
	fmtTypographic uintptr

	allBrushes  []uintptr
	allFonts    []uintptr
	allFamilies []uintptr
	allFormats  []uintptr
}

// initGDIPlus initializes the GDI+ subsystem and creates all drawing resources
func initGDIPlus(hwnd uintptr, width, height int32) (*d2dResources, error) {
	// Load and start GDI+
	// GdiplusStartup(OUT token*, IN input*, IN suppressBackgroundThread)
	input := gdiplusStartupInput{Version: 1}
	status, _, _ := gdipStartup.Call(
		uintptr(unsafe.Pointer(&gdiplusToken)),
		uintptr(unsafe.Pointer(&input)),
		0,
	)
	if status != gpOk {
		return nil, fmt.Errorf("GdiplusStartup failed: status=%d", status)
	}

	res := &d2dResources{hwnd: hwnd, width: width, height: height}

	// Create font families
	segUI := res.createFamily("Segoe UI")
	consolas := res.createFamily("Consolas")
	if segUI == 0 {
		// Fallback to any available font
		segUI = res.createFamily("Arial")
	}
	if consolas == 0 {
		consolas = segUI
	}

	// Create fonts
	res.fmtTitle = res.createFont(segUI, 20, 1) // bold
	res.fmtBody = res.createFont(segUI, 14, 0)
	res.fmtBodyBold = res.createFont(segUI, 14, 1)
	res.fmtSmall = res.createFont(segUI, 12, 0)
	res.fmtMono = res.createFont(consolas, 13, 0)
	res.fmtBtn = res.createFont(segUI, 14, 1)
	res.fmtLabel = res.createFont(segUI, 13, 0)

	// Create brushes
	res.brushBg = res.createBrush(colorBg)
	res.brushCard = res.createBrush(colorCard)
	res.brushPrimary = res.createBrush(colorPrimary)
	res.brushHover = res.createBrush(colorHover)
	res.brushPress = res.createBrush(colorPress)
	res.brushText = res.createBrush(colorText)
	res.brushTextSec = res.createBrush(colorTextSec)
	res.brushBorder = res.createBrush(colorBorder)
	res.brushSuccess = res.createBrush(colorSuccess)
	res.brushError = res.createBrush(colorError)
	res.brushInputBg = res.createBrush(colorInputBg)
	res.brushDisabled = res.createBrush(colorDisabled)
	res.brushShadow = res.createBrush(colorShadow)
	res.brushWhite = res.createBrush(colorFromRGB(255, 255, 255))

	// Create string formats
	res.fmtCenter = res.createStringFormat(gpStringAlignCenter, gpLineAlignCenter)
	res.fmtLeft = res.createStringFormat(gpStringAlignNear, gpLineAlignCenter)
	res.fmtTopLeft = res.createStringFormat(gpStringAlignNear, gpLineAlignNear)
	// Create typographic format for accurate measurement (no padding)
	gdipStringFmtGenericTypographic.Call(uintptr(unsafe.Pointer(&res.fmtTypographic)))
	if res.fmtTypographic != 0 {
		// Set left alignment for typographic format
		gdipSetStringFmtAlign.Call(res.fmtTypographic, uintptr(gpStringAlignNear))
		res.allFormats = append(res.allFormats, res.fmtTypographic)
	}

	return res, nil
}

func (res *d2dResources) createFamily(name string) uintptr {
	namePtr, _ := syscall.UTF16PtrFromString(name)
	var family uintptr
	gdipCreateFontFamily.Call(
		uintptr(unsafe.Pointer(namePtr)),
		0, // null font collection = system fonts
		uintptr(unsafe.Pointer(&family)),
	)
	if family != 0 {
		res.allFamilies = append(res.allFamilies, family)
	}
	return family
}

func (res *d2dResources) createFont(family uintptr, size float32, bold int) uintptr {
	style := 0 // regular
	if bold != 0 {
		style = 1 // bold
	}
	var font uintptr
	gdipCreateFont.Call(
		family,
		f32(size),
		uintptr(style),
		gpUnitPixel,
		uintptr(unsafe.Pointer(&font)),
	)
	if font != 0 {
		res.allFonts = append(res.allFonts, font)
	}
	return font
}

func (res *d2dResources) createBrush(color d2dColorF) uintptr {
	var brush uintptr
	gdipCreateSolidFill.Call(
		uintptr(argbFromColor(color)),
		uintptr(unsafe.Pointer(&brush)),
	)
	if brush != 0 {
		res.allBrushes = append(res.allBrushes, brush)
	}
	return brush
}

func (res *d2dResources) createStringFormat(hAlign, vAlign int) uintptr {
	var fmt uintptr
	gdipCreateStringFmt.Call(0, 0, uintptr(unsafe.Pointer(&fmt)))
	if fmt != 0 {
		gdipSetStringFmtAlign.Call(fmt, uintptr(hAlign))
		gdipSetStringFmtLine.Call(fmt, uintptr(vAlign))
		res.allFormats = append(res.allFormats, fmt)
	}
	return fmt
}

// cleanup releases all GDI+ resources
func (res *d2dResources) cleanup() {
	for _, f := range res.allFormats {
		gdipDeleteStringFmt.Call(f)
	}
	for _, f := range res.allFonts {
		gdipDeleteFont.Call(f)
	}
	for _, f := range res.allFamilies {
		gdipDeleteFontFamily.Call(f)
	}
	for _, b := range res.allBrushes {
		gdipDeleteBrush.Call(b)
	}
	// Release double-buffering resources
	if res.memBmp != 0 {
		procSelectObject.Call(res.memDC, res.oldBmp)
		procDeleteObject.Call(res.memBmp)
		res.memBmp = 0
	}
	if res.memDC != 0 {
		procDeleteDC.Call(res.memDC)
		res.memDC = 0
	}
	if gdiplusToken != 0 {
		gdipShutdown.Call(gdiplusToken)
		gdiplusToken = 0
	}
}

// resize updates stored dimensions (GDI+ creates fresh Graphics each paint)
func (res *d2dResources) resize(width, height int32) {
	res.width = width
	res.height = height
}

// invalidate triggers a repaint
func (res *d2dResources) invalidate() {
	if res.hwnd != 0 {
		procInvalidateRect.Call(res.hwnd, 0, 0)
	}
}

// === Drawing functions ===

// beginDraw sets up a double-buffered memory DC for flicker-free rendering.
// Caller must set res.paintHDC (from BeginPaint) before calling this.
func (res *d2dResources) beginDraw() {
	hdc := res.paintHDC
	if hdc == 0 {
		return
	}

	// Create memory DC (persistent across paint cycles)
	if res.memDC == 0 {
		res.memDC, _, _ = procCreateCompatibleDC.Call(hdc)
	}
	if res.memDC == 0 {
		return
	}

	// Recreate DIB section if size changed
	w := res.width
	h := res.height
	if w <= 0 {
		w = 1
	}
	if h <= 0 {
		h = 1
	}
	if res.memBmp != 0 {
		procSelectObject.Call(res.memDC, res.oldBmp)
		procDeleteObject.Call(res.memBmp)
		res.memBmp = 0
	}

	bi := bitmapInfo{
		Header: bitmapInfoHeader{
			Size:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			Width:    w,
			Height:   -h, // top-down DIB
			Planes:   1,
			BitCount: 32,
		},
	}
	var bits uintptr
	ret, _, _ := procCreateDIBSection.Call(
		hdc, uintptr(unsafe.Pointer(&bi)),
		dibRgbColors, uintptr(unsafe.Pointer(&bits)), 0, 0,
	)
	if ret == 0 {
		return
	}
	res.memBmp = ret
	res.oldBmp, _, _ = procSelectObject.Call(res.memDC, res.memBmp)

	// Create GDI+ Graphics from the memory DC
	gdipCreateFromHDC.Call(res.memDC, uintptr(unsafe.Pointer(&res.gfx)))
	if res.gfx != 0 {
		gdipSetSmoothingMode.Call(res.gfx, gpSmoothingAntiAlias)
		gdipSetTextRendering.Call(res.gfx, gpTextRenderClearType)
	}
}

// endDraw blits the memory DC to the paint HDC, then cleans up.
func (res *d2dResources) endDraw() {
	if res.gfx != 0 {
		gdipDeleteGraphics.Call(res.gfx)
		res.gfx = 0
	}
	if res.paintHDC != 0 && res.memDC != 0 && res.memBmp != 0 {
		procBitBlt.Call(res.paintHDC,
			0, 0, uintptr(res.width), uintptr(res.height),
			res.memDC, 0, 0, srccopy)
	}
	if res.memBmp != 0 {
		procSelectObject.Call(res.memDC, res.oldBmp)
		procDeleteObject.Call(res.memBmp)
		res.memBmp = 0
	}
	res.paintHDC = 0
}

// clear fills the entire surface with a color
func (res *d2dResources) clear(color d2dColorF) {
	if res.gfx == 0 {
		return
	}
	gdipGraphicsClear.Call(res.gfx, uintptr(argbFromColor(color)))
}

// buildRoundedPath creates a GpPath for a rounded rectangle
func (res *d2dResources) buildRoundedPath(left, top, right, bottom, rx, ry float32) uintptr {
	var path uintptr
	gdipCreatePath.Call(gpFillModeAlternate, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return 0
	}

	w := right - left
	h := bottom - top
	d := rx * 2 // arc diameter

	// Top-left arc
	gdipAddPathArc.Call(path, f32(left), f32(top), f32(d), f32(d), f32(180), f32(90))
	// Top-right arc
	gdipAddPathArc.Call(path, f32(left+w-d), f32(top), f32(d), f32(d), f32(270), f32(90))
	// Bottom-right arc
	gdipAddPathArc.Call(path, f32(left+w-d), f32(top+h-d), f32(d), f32(d), f32(0), f32(90))
	// Bottom-left arc
	gdipAddPathArc.Call(path, f32(left), f32(top+h-d), f32(d), f32(d), f32(90), f32(90))
	gdipClosePathFigure.Call(path)

	return path
}

// fillRoundedRect fills a rounded rectangle using a pre-created brush
func (res *d2dResources) fillRoundedRect(brush uintptr, left, top, right, bottom, rx, ry float32) {
	if res.gfx == 0 || brush == 0 {
		return
	}
	path := res.buildRoundedPath(left, top, right, bottom, rx, ry)
	if path == 0 {
		return
	}
	defer gdipDeletePath.Call(path)
	gdipFillPath.Call(res.gfx, brush, path)
}

// drawRoundedRect draws a rounded rectangle outline
func (res *d2dResources) drawRoundedRect(brush uintptr, left, top, right, bottom, rx, ry, strokeWidth float32) {
	if res.gfx == 0 || brush == 0 {
		return
	}
	path := res.buildRoundedPath(left, top, right, bottom, rx, ry)
	if path == 0 {
		return
	}
	defer gdipDeletePath.Call(path)

	// Create a temporary pen from the brush
	var pen uintptr
	gdipCreatePen2.Call(brush, f32(strokeWidth), gpUnitPixel, uintptr(unsafe.Pointer(&pen)))
	if pen == 0 {
		return
	}
	defer gdipDeletePen.Call(pen)
	gdipDrawPath.Call(res.gfx, pen, path)
}

// drawLine draws a line
func (res *d2dResources) drawLine(brush uintptr, x0, y0, x1, y1, strokeWidth float32) {
	if res.gfx == 0 || brush == 0 {
		return
	}
	var pen uintptr
	gdipCreatePen2.Call(brush, f32(strokeWidth), gpUnitPixel, uintptr(unsafe.Pointer(&pen)))
	if pen == 0 {
		return
	}
	defer gdipDeletePen.Call(pen)
	gdipDrawLine.Call(res.gfx, pen, f32(x0), f32(y0), f32(x1), f32(y1))
}

// drawText draws text in a layout rectangle using a font and brush.
// Uses centered format for buttons (short text), left-aligned for everything else.
func (res *d2dResources) drawText(text string, font uintptr, brush uintptr, left, top, right, bottom float32) {
	res.drawTextAligned(text, font, brush, left, top, right, bottom, true)
}

func (res *d2dResources) drawTextLeft(text string, font uintptr, brush uintptr, left, top, right, bottom float32) {
	res.drawTextAligned(text, font, brush, left, top, right, bottom, false)
}

func (res *d2dResources) drawTextAligned(text string, font uintptr, brush uintptr, left, top, right, bottom float32, centerH bool) {
	if res.gfx == 0 || font == 0 || brush == 0 || text == "" {
		return
	}
	textPtr, _ := syscall.UTF16PtrFromString(text)
	if textPtr == nil {
		return
	}
	textLen := int32(len([]rune(text)))

	// Use centered format for short text (buttons), top-left for multi-line
	// Use typographic format for single-line left-aligned text (no padding)
	runes := []rune(text)
	strFmt := res.fmtTopLeft
	if centerH && len(runes) <= 20 && !strings.Contains(text, "\n") {
		strFmt = res.fmtCenter
	} else if !centerH && len(runes) <= 20 && !strings.Contains(text, "\n") {
		// Use typographic format for accurate positioning (no padding)
		if res.fmtTypographic != 0 {
			strFmt = res.fmtTypographic
		} else {
			strFmt = res.fmtLeft
		}
	}

	var layoutRect d2dRectF
	layoutRect = d2dRectF{left, top, right - left, bottom - top}

	gdipDrawString.Call(
		res.gfx,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(textLen),
		font,
		uintptr(unsafe.Pointer(&layoutRect)),
		strFmt,
		brush,
	)
}

// drawShadow draws shadow layers behind a rounded rect
func (res *d2dResources) drawShadow(left, top, right, bottom, rx, ry float32, layers int) {
	if res.gfx == 0 {
		return
	}
	for i := 1; i <= layers; i++ {
		offset := float32(i)
		alpha := uint8(15 - i*3)
		if alpha <= 0 {
			alpha = 1
		}
		c := argb(0, 0, 0, alpha)
		var brush uintptr
		gdipCreateSolidFill.Call(uintptr(c), uintptr(unsafe.Pointer(&brush)))
		if brush == 0 {
			continue
		}
		path := res.buildRoundedPath(left+offset, top+offset, right+offset, bottom+offset, rx, ry)
		if path != 0 {
			gdipFillPath.Call(res.gfx, brush, path)
			gdipDeletePath.Call(path)
		}
		gdipDeleteBrush.Call(brush)
	}
}

// clipPush sets a rectangular clipping region
func (res *d2dResources) clipPush(left, top, right, bottom float32) {
	if res.gfx == 0 {
		return
	}
	gdipSetClipRect.Call(
		res.gfx,
		f32(left), f32(top), f32(right-left), f32(bottom-top),
		0, // CombineModeReplace
	)
}

// clipPop resets the clipping region
func (res *d2dResources) clipPop() {
	if res.gfx == 0 {
		return
	}
	gdipResetClip.Call(res.gfx)
}

// setBrushColor updates a brush's color
func (res *d2dResources) setBrushColor(brush uintptr, color d2dColorF) {
	if brush == 0 {
		return
	}
	gdipSetSolidFillColor.Call(brush, uintptr(argbFromColor(color)))
}

// measureTextWidth measures the pixel width of a string using a given font.
// Uses GenericTypographic format to eliminate padding for accurate cursor positioning.
// Returns 0 if measurement fails.
func (res *d2dResources) measureTextWidth(text string, font uintptr) float32 {
	if res.gfx == 0 || font == 0 || text == "" {
		return 0
	}
	textPtr, _ := syscall.UTF16PtrFromString(text)
	if textPtr == nil {
		return 0
	}
	textLen := int32(len([]rune(text)))
	layoutRect := d2dRectF{0, 0, 10000, 1000}
	var codepointsFitted, linesFilled int32
	var bbox [4]float32 // x, y, width, height
	// Use typographic format for accurate measurement (no padding)
	fmt := res.fmtTypographic
	if fmt == 0 {
		fmt = res.fmtLeft // fallback
	}
	gdipMeasureStr.Call(
		res.gfx,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(textLen),
		font,
		uintptr(unsafe.Pointer(&layoutRect)),
		fmt,
		uintptr(unsafe.Pointer(&bbox[0])),
		uintptr(unsafe.Pointer(&codepointsFitted)),
		uintptr(unsafe.Pointer(&linesFilled)),
	)
	return bbox[2] // width
}

// iconInfo struct for CreateIconIndirect
type iconInfo struct {
	IsIcon   int32
	XHotspot uint32
	YHotspot uint32
	MaskBmp  uintptr
	ColorBmp uintptr
}

// createWindowIcon creates and sets a custom icon with white letter "G" on blue background.
func createWindowIcon(hwnd uintptr) {
	// Get screen DC for creating compatible bitmaps
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return
	}
	defer procReleaseDC.Call(0, screenDC)

	const sz = 32
	hdr := bitmapInfoHeader{
		Size:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		Width:       sz,
		Height:      -sz, // top-down
		Planes:      1,
		BitCount:    32,
		Compression: biRgb,
	}
	bi := bitmapInfo{Header: hdr}

	// Create 32bpp color DIB
	var colorBits uintptr
	colorBmp, _, _ := procCreateDIBSection.Call(
		screenDC, uintptr(unsafe.Pointer(&bi)), dibRgbColors,
		uintptr(unsafe.Pointer(&colorBits)), 0, 0,
	)
	if colorBmp == 0 {
		return
	}

	// Fill with pixel data
	pixels := unsafe.Slice((*uint32)(unsafe.Pointer(colorBits)), sz*sz)
	blue := uint32(0xFF0078D4)  // BGR: #0078D4 (Windows blue) - format: 0xAARRGGBB
	white := uint32(0xFFFFFFFF)

	// Fill background with blue
	for i := range pixels {
		pixels[i] = blue
	}

	// Draw white letter "G" (simplified bitmap font)
	// G shape: top arc, left vertical, bottom arc, right middle horizontal
	gPixels := [][2]int{
		// Top arc
		{12, 6}, {13, 6}, {14, 5}, {15, 5}, {16, 5}, {17, 5}, {18, 5}, {19, 6}, {20, 6},
		// Left vertical
		{11, 7}, {11, 8}, {11, 9}, {11, 10}, {11, 11}, {11, 12}, {11, 13}, {11, 14},
		{11, 15}, {11, 16}, {11, 17}, {11, 18}, {11, 19}, {11, 20}, {11, 21}, {11, 22}, {11, 23},
		// Bottom arc
		{12, 24}, {13, 24}, {14, 25}, {15, 25}, {16, 25}, {17, 25}, {18, 25}, {19, 24}, {20, 24},
		// Right vertical (lower half)
		{20, 16}, {20, 17}, {20, 18}, {20, 19}, {20, 20}, {20, 21}, {20, 22}, {20, 23},
		// Middle horizontal bar
		{15, 16}, {16, 16}, {17, 16}, {18, 16}, {19, 16},
	}

	// Draw with anti-aliasing (2px thickness)
	for _, pt := range gPixels {
		x, y := pt[0], pt[1]
		if x >= 0 && x < sz && y >= 0 && y < sz {
			pixels[y*sz+x] = white
			// Add thickness
			if x+1 < sz {
				pixels[y*sz+x+1] = white
			}
		}
	}

	// Create 1bpp monochrome mask (all 0 = fully opaque)
	maskHdr := bitmapInfoHeader{
		Size:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		Width:       sz,
		Height:      -sz,
		Planes:      1,
		BitCount:    1,
		Compression: biRgb,
	}
	maskBi := bitmapInfo{Header: maskHdr}
	var maskBits uintptr
	maskBmp, _, _ := procCreateDIBSection.Call(
		screenDC, uintptr(unsafe.Pointer(&maskBi)), dibRgbColors,
		uintptr(unsafe.Pointer(&maskBits)), 0, 0,
	)
	if maskBits != 0 {
		// Zero the mask (32 rows × 4 bytes per row = 128 bytes)
		maskData := unsafe.Slice((*byte)(unsafe.Pointer(maskBits)), 128)
		for i := range maskData {
			maskData[i] = 0
		}
	}

	// Create icon from color + mask bitmaps
	ii := iconInfo{
		IsIcon:   1,
		XHotspot: 0,
		YHotspot: 0,
		MaskBmp:  maskBmp,
		ColorBmp: colorBmp,
	}
	hIcon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	if hIcon != 0 {
		procSendMessageW.Call(hwnd, wmSetIcon, iconBig, hIcon)
		procSendMessageW.Call(hwnd, wmSetIcon, iconSmall, hIcon)
	}

	// Cleanup bitmaps (icon has its own copy)
	procDeleteObject.Call(colorBmp)
	if maskBmp != 0 {
		procDeleteObject.Call(maskBmp)
	}
}
