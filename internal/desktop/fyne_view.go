//go:build fyne

package desktop

import (
	"context"
	"fmt"
	"strings"

	"anixops-sd-wan/internal/domain"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func NewOverviewCanvas(model ViewModel, client *AgentClient, autostartOpts AutostartOptions) fyne.CanvasObject {
	var tabs []*container.TabItem
	for _, page := range model.Pages() {
		tabs = append(tabs, container.NewTabItem(page.Title, renderPage(page, model, client, autostartOpts)))
	}
	return container.NewBorder(widget.NewLabel("AnixOps Desktop"), nil, nil, nil, container.NewAppTabs(tabs...))
}

func renderPage(page DesktopPage, model ViewModel, client *AgentClient, autostartOpts AutostartOptions) fyne.CanvasObject {
	items := make([]fyne.CanvasObject, 0, len(page.Lines)+1)
	items = append(items, widget.NewLabelWithStyle(page.Title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
	for _, line := range page.Lines {
		items = append(items, widget.NewLabel(line))
	}
	if (page.Title == "Settings" || page.Title == "Protocol switching") && client != nil {
		items = append(items,
			widget.NewSeparator(),
			renderConfigControlSection(page.Title, model, client, autostartOpts),
		)
	}
	if page.Title == "Settings" {
		items = append(items,
			widget.NewSeparator(),
			renderAutostartSection(autostartOpts),
		)
	}
	if page.Title == "Diagnostics" {
		items = append(items,
			widget.NewSeparator(),
			renderSelfCheckSection(model),
		)
	}
	if len(page.Lines) == 0 {
		items = append(items, widget.NewLabel("No data available"))
	}
	return container.NewScroll(container.NewVBox(items...))
}

func renderSelfCheckSection(model ViewModel) fyne.CanvasObject {
	status := widget.NewLabel("Ready to run")
	result := widget.NewLabel("")
	run := widget.NewButton("Run Self-check", func() {
		check := RunSelfCheck(model)
		if check.Passed {
			status.SetText("Self-check passed")
		} else {
			status.SetText("Self-check needs attention")
		}
		result.SetText(strings.Join(check.Lines, "\n"))
	})
	return container.NewVBox(
		widget.NewLabelWithStyle("Self-check", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		run,
		status,
		result,
	)
}

func renderConfigControlSection(title string, model ViewModel, client *AgentClient, autostartOpts AutostartOptions) fyne.CanvasObject {
	idEntry := widget.NewEntry()
	configID := model.Config.ID
	if configID == "" {
		configID = "ui-" + model.ConfigVersion
	}
	idEntry.SetText(configID)

	transportEntry := widget.NewSelect([]string{"native-wireguard", "hysteria2", "reality", "tuic"}, nil)
	transportValue := model.Config.Values["transport"]
	if transportValue == "" {
		transportValue = model.Link.Protocol.String()
	}
	transportEntry.SetSelected(transportValue)

	versionEntry := widget.NewEntry()
	if model.Config.Version != "" {
		versionEntry.SetText(model.Config.Version)
	} else {
		versionEntry.SetText(model.ConfigVersion)
	}

	status := widget.NewLabel("")
	buttonLabel := "Apply Config"
	sectionLabel := "Apply Config"
	if title == "Protocol switching" {
		buttonLabel = "Switch Protocol"
		sectionLabel = "Switch Protocol"
	}
	apply := widget.NewButton(buttonLabel, func() {
		bundle := domain.ConfigBundle{
			ID:       idEntry.Text,
			TenantID: model.TenantID,
			TargetID: model.DeviceID,
			Version:  versionEntry.Text,
			Values: map[string]string{
				"transport": transportEntry.Selected,
			},
		}
		status.SetText("applying config...")
		snapshot, err := client.ApplyConfig(context.Background(), bundle)
		if err != nil {
			status.SetText(fmt.Sprintf("apply failed: %v", err))
			return
		}
		status.SetText("applied config version " + snapshot.ConfigVersion)
	})
	items := []fyne.CanvasObject{
		widget.NewLabelWithStyle(sectionLabel, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("Config ID", idEntry),
			widget.NewFormItem("Version", versionEntry),
			widget.NewFormItem("Transport", transportEntry),
		),
		apply,
		status,
	}
	return container.NewVBox(items...)
}

func renderAutostartSection(opts AutostartOptions) fyne.CanvasObject {
	stateText := "Current state: unavailable"
	if enabled, path, err := AutostartState(opts); err == nil {
		if enabled {
			stateText = "Current state: enabled (" + path + ")"
		} else {
			stateText = "Current state: disabled (" + path + ")"
		}
	}
	status := widget.NewLabel("")
	enabled := widget.NewButton("Enable Start at Login", func() {
		plan, err := EnableAutostart(opts)
		if err != nil {
			status.SetText("autostart enable failed: " + err.Error())
			return
		}
		status.SetText("autostart enabled: " + plan.Path)
	})
	disabled := widget.NewButton("Disable Start at Login", func() {
		path, err := DisableAutostart(opts)
		if err != nil {
			status.SetText("autostart disable failed: " + err.Error())
			return
		}
		status.SetText("autostart disabled: " + path)
	})
	return container.NewVBox(
		widget.NewLabelWithStyle("Start at login", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(stateText),
		enabled,
		disabled,
		status,
	)
}
