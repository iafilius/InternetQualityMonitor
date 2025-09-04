package main

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/widget"
)

func main() {
	fmt.Println("[fyneprobe] starting minimal Fyne app")
	a := app.New()
	w := a.NewWindow("Fyne Probe")
	w.SetContent(widget.NewLabel("Minimal Fyne window - will close in 5s"))
	go func() {
		time.Sleep(5 * time.Second)
		fmt.Println("[fyneprobe] closing window via fyne.Do")
		fyne.Do(func() { w.Close() })
	}()
	w.ShowAndRun()
	fmt.Println("[fyneprobe] exited cleanly")
}
