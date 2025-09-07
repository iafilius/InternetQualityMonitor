//go:build crosshair
// +build crosshair

package main

import (
	"math"
	"time"
)

// nearestIndexAndLineXFromCenters picks nearest index to mouseX given precomputed centers.
func nearestIndexAndLineXFromCenters(centers []float32, mouseX float32) (int, float32) {
	if len(centers) == 0 {
		return 0, 0
	}
	best := 0
	bestD := float32(math.MaxFloat32)
	for i, c := range centers {
		d := float32(math.Abs(float64(mouseX - c)))
		if d < bestD {
			bestD = d
			best = i
		}
	}
	return best, centers[best]
}

// xCentersTimeMode computes pixel x positions for time-based x-axis, proportional to time span.
func xCentersTimeMode(times []time.Time, imgW, imgH, viewW, viewH float32) []float32 {
	n := len(times)
	if n == 0 {
		return nil
	}
	drawX, _, _, _, scale := computeContainRect(imgW, imgH, viewW, viewH)
	leftPadImg := float32(16) + axisLeftGutterPx
	rightPadImg := float32(12) + axisRightGutterPx
	plotWImg := imgW - leftPadImg - rightPadImg
	if plotWImg < 1 {
		plotWImg = imgW
	}
	tmin := times[0]
	tmax := times[0]
	for _, t := range times {
		if t.Before(tmin) {
			tmin = t
		}
		if t.After(tmax) {
			tmax = t
		}
	}
	span := tmax.Sub(tmin).Seconds()
	if span <= 0 {
		return xCentersIndexMode(n, imgW, imgH, viewW, viewH)
	}
	px := make([]float32, n)
	for i, t := range times {
		dx := float32(t.Sub(tmin).Seconds() / span)
		pxImg := leftPadImg + plotWImg*dx
		px[i] = drawX + pxImg*scale
	}
	return px
}
