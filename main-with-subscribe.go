package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed bin/*
var binData embed.FS

type ClashController struct {
	clashCmd        *exec.Cmd
	running         bool
	mu              sync.Mutex
	statusLabel     *widget.Label
	controlBtn      *widget.Button
	nodeInfoLabel   *widget.Label
	memoryLabel     *widget.Label
	window          fyne.Window
	clashPath       string
	configPath      string
	proxyStatus     bool
	proxyStatusLbl  *widget.Label
	proxyToggleBtn  *widget.Button
	stopMonitor     chan struct{}
	appDataDir      string
	clashPID        int
	deviceID        string
	subscriptionURL string
	autoUpdate      bool
	updateInterval  int
	updateTicker    *time.Ticker
	updateStopChan  chan struct{}
	googleStatus    string
	baiduStatus     string
	googleStatusLbl *widget.Label
	baiduStatusLbl  *widget.Label
}

type Proxy struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Now     string `json:"now"`
	History []struct {
		Time      time.Time `json:"time"`
		Delay     int       `json:"delay"`
		MeanDelay int       `json:"meanDelay"`
	} `json:"history"`
}

type ProxyNode struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	History []struct {
		Time  time.Time `json:"time"`
		Delay int       `json:"delay"`
	} `json:"history"`
}

func main() {
	myApp := app.NewWithID("com.github.clash.client")
	myWindow := myApp.NewWindow("Clash 代理控制器")
	myWindow.Resize(fyne.NewSize(500, 550))

	appDataDir, err := getAppDataDir()
	if err != nil {
		dialog.ShowError(fmt.Errorf("无法创建应用数据目录: %v", err), myWindow)
		return
	}

	deviceID := getDeviceID()

	binDir := filepath.Join(appDataDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		dialog.ShowError(fmt.Errorf("无法创建bin目录: %v", err), myWindow)
		return
	}

	clashPath, err := extractClashBin(binDir)
	if err != nil {
		dialog.ShowError(fmt.Errorf("提取Clash失败: %v", err), myWindow)
		return
	}

	configPath := filepath.Join(appDataDir, "config.yaml")
	settingsPath := filepath.Join(appDataDir, "settings.json")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := createDefaultConfig(configPath); err != nil {
			dialog.ShowError(fmt.Errorf("创建配置文件失败: %v", err), myWindow)
			return
		}
	}

	controller := &ClashController{
		running:        false,
		window:         myWindow,
		clashPath:      clashPath,
		configPath:     configPath,
		stopMonitor:    make(chan struct{}),
		appDataDir:     appDataDir,
		deviceID:       deviceID,
		updateStopChan: make(chan struct{}),
	}

	controller.loadSettings(settingsPath)

	title := widget.NewLabelWithStyle("Clash 代理控制器", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	title.TextStyle.Bold = true

	deviceIDLabel := widget.NewLabel("设备ID:")
	deviceIDEntry := widget.NewEntry()
	deviceIDEntry.SetText(deviceID)
	deviceIDEntry.Disable()
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		myWindow.Clipboard().SetContent(deviceID)
		dialog.ShowInformation("已复制", "设备ID已复制到剪贴板", myWindow)
	})
	copyBtn.Importance = widget.LowImportance
	deviceIDContainer := container.NewBorder(
		nil,
		nil,
		deviceIDLabel,
		copyBtn,
		deviceIDEntry,
	)
	helpText := widget.NewLabel("此ID用于服务器识别您的设备")
	helpText.TextStyle.Italic = true
	helpText.Alignment = fyne.TextAlignCenter
	deviceIDBox := container.NewVBox(
		deviceIDContainer,
		helpText,
	)

	controller.statusLabel = widget.NewLabel("状态: 代理未运行")
	controller.statusLabel.Alignment = fyne.TextAlignCenter

	controller.controlBtn = widget.NewButton("启动代理", controller.toggleClash)
	controller.controlBtn.Importance = widget.HighImportance

	nodeTitle := widget.NewLabelWithStyle("节点信息", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	controller.nodeInfoLabel = widget.NewLabel("当前节点: -\n延迟: -\n更新时间: -")
	controller.nodeInfoLabel.Wrapping = fyne.TextWrapWord

	memoryTitle := widget.NewLabelWithStyle("资源占用", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	controller.memoryLabel = widget.NewLabel("内存: -\n更新时间: -")
	controller.memoryLabel.Wrapping = fyne.TextWrapWord

	refreshBtn := widget.NewButton("刷新节点信息", controller.refreshNodeInfo)

	remoteConfigBtn := widget.NewButton("更新配置", controller.updateRemoteConfig)

	subscriptionLabel := widget.NewLabel("订阅URL:")
	subscriptionEntry := widget.NewEntry()
	subscriptionEntry.SetText(controller.subscriptionURL)
	subscriptionEntry.OnChanged = func(url string) {
		controller.subscriptionURL = strings.TrimSpace(url)
	}

	autoUpdateCheck := widget.NewCheck("自动更新订阅", func(checked bool) {
		controller.autoUpdate = checked
		if checked {
			controller.startAutoUpdate()
		} else {
			controller.stopAutoUpdate()
		}
	})
	autoUpdateCheck.SetChecked(controller.autoUpdate)

	intervalLabel := widget.NewLabel("更新间隔(分钟):")
	intervalEntry := widget.NewEntry()
	intervalEntry.SetText(strconv.Itoa(controller.updateInterval))
	intervalEntry.OnChanged = func(text string) {
		if val, err := strconv.Atoi(text); err == nil && val > 0 {
			controller.updateInterval = val
			if controller.autoUpdate {
				controller.restartAutoUpdate()
			}
		}
	}

	subscriptionBox := container.NewVBox(
		widget.NewLabelWithStyle("订阅设置", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWithColumns(2,
			subscriptionLabel,
			subscriptionEntry,
		),
		container.NewHBox(
			autoUpdateCheck,
			intervalLabel,
			intervalEntry,
		),
	)

	// 添加连通性测试区域
	connectivityTitle := widget.NewLabelWithStyle("连通性测试", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	googleLabel := widget.NewLabel("Google:")
	controller.googleStatusLbl = widget.NewLabel("未测试")
	controller.googleStatusLbl.Alignment = fyne.TextAlignTrailing
	baiduLabel := widget.NewLabel("Baidu:")
	controller.baiduStatusLbl = widget.NewLabel("未测试")
	controller.baiduStatusLbl.Alignment = fyne.TextAlignTrailing

	connectivityGrid := container.NewGridWithColumns(2,
		container.NewHBox(googleLabel, controller.googleStatusLbl),
		container.NewHBox(baiduLabel, controller.baiduStatusLbl),
	)

	testBtn := widget.NewButton("测试连通性", controller.testConnectivity)
	connectivityBox := container.NewVBox(
		connectivityTitle,
		connectivityGrid,
		container.NewHBox(layout.NewSpacer(), testBtn, layout.NewSpacer()),
	)

	controller.proxyStatusLbl = widget.NewLabel("系统代理状态: 检测中...")
	controller.proxyStatusLbl.Alignment = fyne.TextAlignCenter
	controller.proxyToggleBtn = widget.NewButton("设置系统代理", controller.toggleSystemProxy)
	controller.proxyToggleBtn.Importance = widget.MediumImportance

	exitBtn := widget.NewButton("退出程序", func() {
		controller.exitApplication(settingsPath)
	})
	exitBtn.Importance = widget.DangerImportance

	header := container.NewVBox(
		title,
		deviceIDBox,
		widget.NewSeparator(),
	)

	statusBox := container.NewHBox(
		layout.NewSpacer(),
		controller.statusLabel,
		layout.NewSpacer(),
		controller.controlBtn,
		layout.NewSpacer(),
	)

	infoGrid := container.NewGridWithColumns(2,
		container.NewVBox(nodeTitle, controller.nodeInfoLabel),
		container.NewVBox(memoryTitle, controller.memoryLabel),
	)
	infoGridContainer := container.NewScroll(infoGrid)
	infoGridContainer.SetMinSize(fyne.NewSize(0, 120))

	buttonBox := container.NewHBox(
		layout.NewSpacer(),
		refreshBtn,
		layout.NewSpacer(),
		remoteConfigBtn,
		layout.NewSpacer(),
	)

	proxyBox := container.NewVBox(
		controller.proxyStatusLbl,
		container.NewHBox(layout.NewSpacer(), controller.proxyToggleBtn, layout.NewSpacer()),
	)

	bottomBox := container.NewHBox(
		layout.NewSpacer(),
		exitBtn,
		layout.NewSpacer(),
	)

	content := container.NewBorder(
		header,
		container.NewVBox(
			widget.NewSeparator(),
			proxyBox,
			widget.NewSeparator(),
			bottomBox,
		),
		nil,
		nil,
		container.NewVBox(
			statusBox,
			widget.NewSeparator(),
			subscriptionBox,
			widget.NewSeparator(),
			infoGridContainer,
			widget.NewSeparator(),
			connectivityBox,
			widget.NewSeparator(),
			buttonBox,
		),
	)

	myApp.Settings().SetTheme(theme.LightTheme())

	myWindow.SetContent(content)

	go controller.checkSystemProxy()

	if controller.autoUpdate {
		controller.startAutoUpdate()
	}

	myWindow.SetCloseIntercept(func() {
		controller.exitApplication(settingsPath)
	})

	myWindow.ShowAndRun()
}

func (c *ClashController) testConnectivity() {
	c.googleStatusLbl.SetText("测试中...")
	c.baiduStatusLbl.SetText("测试中...")

	go func() {
		// 测试Google连通性
		googleOK := testConnection("https://www.google.com", 5*time.Second)
		if googleOK {
			c.googleStatus = "可达"
			c.googleStatusLbl.SetText("可达")
		} else {
			c.googleStatus = "不可达"
			c.googleStatusLbl.SetText("不可达")
		}

		// 测试Baidu连通性
		baiduOK := testConnection("https://www.baidu.com", 2*time.Second)
		if baiduOK {
			c.baiduStatus = "可达"
			c.baiduStatusLbl.SetText("可达")
		} else {
			c.baiduStatus = "不可达"
			c.baiduStatusLbl.SetText("不可达")
		}
	}()
}

func testConnection(url string, timeout time.Duration) bool {
	client := http.Client{
		Timeout: timeout,
	}

	// 尝试HEAD请求（更快）
	resp, err := client.Head(url)
	if err == nil && resp.StatusCode < 400 {
		return true
	}

	// 如果HEAD失败，尝试GET请求
	resp, err = client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 400
}

func (c *ClashController) loadSettings(settingsPath string) {
	c.autoUpdate = false
	c.updateInterval = 60

	if _, err := os.Stat(settingsPath); os.IsNotExist(err) {
		return
	}

	data, err := ioutil.ReadFile(settingsPath)
	if err != nil {
		return
	}

	var settings struct {
		SubscriptionURL string `json:"subscriptionUrl"`
		AutoUpdate      bool   `json:"autoUpdate"`
		UpdateInterval  int    `json:"updateInterval"`
	}

	if err := json.Unmarshal(data, &settings); err == nil {
		c.subscriptionURL = settings.SubscriptionURL
		c.autoUpdate = settings.AutoUpdate
		if settings.UpdateInterval > 0 {
			c.updateInterval = settings.UpdateInterval
		}
	}
}

func (c *ClashController) saveSettings(settingsPath string) {
	settings := struct {
		SubscriptionURL string `json:"subscriptionUrl"`
		AutoUpdate      bool   `json:"autoUpdate"`
		UpdateInterval  int    `json:"updateInterval"`
	}{
		SubscriptionURL: c.subscriptionURL,
		AutoUpdate:      c.autoUpdate,
		UpdateInterval:  c.updateInterval,
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return
	}

	ioutil.WriteFile(settingsPath, data, 0644)
}

func (c *ClashController) startAutoUpdate() {
	if c.updateTicker != nil {
		c.updateTicker.Stop()
	}

	c.updateTicker = time.NewTicker(time.Duration(c.updateInterval) * time.Minute)
	c.updateStopChan = make(chan struct{})

	go func() {
		c.downloadConfig(c.subscriptionURL, true) // 启动时立即更新一次

		for {
			select {
			case <-c.updateTicker.C:
				if c.subscriptionURL != "" {
					c.downloadConfig(c.subscriptionURL, true)
				}
			case <-c.updateStopChan:
				return
			}
		}
	}()
}

func (c *ClashController) stopAutoUpdate() {
	if c.updateTicker != nil {
		c.updateTicker.Stop()
	}
	close(c.updateStopChan)
}

func (c *ClashController) restartAutoUpdate() {
	c.stopAutoUpdate()
	c.startAutoUpdate()
}

func getDeviceID() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.READ)
	if err != nil {
		return fallbackDeviceID()
	}
	defer key.Close()

	guid, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return fallbackDeviceID()
	}
	return guid
}

func fallbackDeviceID() string {
	volName := "C:\\"
	var volSerial uint32
	err := windows.GetVolumeInformation(
		windows.StringToUTF16Ptr(volName),
		nil,
		0,
		&volSerial,
		nil,
		nil,
		nil,
		0,
	)
	if err != nil {
		return fmt.Sprintf("rand-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("vol-%d", volSerial)
}

func getAppDataDir() (string, error) {
	appDataDir := filepath.Join(os.Getenv("APPDATA"), "ClashClient")
	if err := os.MkdirAll(appDataDir, 0755); err != nil {
		return "", err
	}
	return appDataDir, nil
}

func extractClashBin(binDir string) (string, error) {
	binName := "clash-windows-amd64.exe"

	data, err := binData.ReadFile("bin/" + binName)
	if err != nil {
		return "", fmt.Errorf("无法读取嵌入文件: %v", err)
	}

	binPath := filepath.Join(binDir, binName)
	if err := ioutil.WriteFile(binPath, data, 0755); err != nil {
		return "", fmt.Errorf("无法写入文件: %v", err)
	}

	return binPath, nil
}

func createDefaultConfig(configPath string) error {
	defaultConfig := `
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
  - name: "示例节点"
    type: http
    server: example.com
    port: 8080

proxy-groups:
  - name: "亚洲负载均衡"
    type: select
    proxies:
      - "示例节点"

rules:
  - DOMAIN-SUFFIX,google.com,亚洲负载均衡
  - DOMAIN-KEYWORD,github,亚洲负载均衡
  - GEOIP,CN,DIRECT
  - MATCH,亚洲负载均衡
`

	return ioutil.WriteFile(configPath, []byte(defaultConfig), 0644)
}

func (c *ClashController) toggleClash() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		c.stopClash()
	} else {
		c.startClash()
	}
}

func (c *ClashController) startClash() {
	c.statusLabel.SetText("状态: 启动中...")
	c.controlBtn.Disable()
	c.nodeInfoLabel.SetText("当前节点: 启动中...")
	c.memoryLabel.SetText("内存: 启动中...")

	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		cmd := exec.Command(c.clashPath, "-f", c.configPath)
		cmd.Dir = filepath.Dir(c.clashPath)
		cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}

		if err := cmd.Start(); err != nil {
			c.nodeInfoLabel.SetText("启动错误: " + err.Error())
			c.statusLabel.SetText("启动失败")
			c.controlBtn.Enable()
			return
		}

		c.clashCmd = cmd
		c.clashPID = cmd.Process.Pid
		c.running = true

		c.statusLabel.SetText("状态: 代理运行中 (127.0.0.1:7890)")
		c.controlBtn.SetText("关闭代理")
		c.controlBtn.Importance = widget.DangerImportance
		c.controlBtn.Enable()

		go c.monitorActiveNodes()

		go func() {
			err := cmd.Wait()
			if err != nil {
				c.nodeInfoLabel.SetText("代理停止: " + err.Error())
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			c.running = false

			close(c.stopMonitor)
			c.stopMonitor = make(chan struct{})

			c.statusLabel.SetText("状态: 代理已停止")
			c.controlBtn.SetText("启动代理")
			c.controlBtn.Importance = widget.HighImportance
			c.nodeInfoLabel.SetText("当前节点: 代理已停止")
			c.memoryLabel.SetText("内存: 代理已停止")
		}()
	}()
}

func (c *ClashController) monitorActiveNodes() {
	time.Sleep(2 * time.Second)
	c.refreshNodeInfo()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.refreshNodeInfo()
		case <-c.stopMonitor:
			return
		}
	}
}

func (c *ClashController) refreshNodeInfo() {
	if !c.running || c.clashCmd == nil || c.clashCmd.Process == nil {
		return
	}

	nodeInfo, delay, err := c.getActiveNode()
	if err != nil {
		c.nodeInfoLabel.SetText(fmt.Sprintf("当前节点: -\n延迟: -\n错误: %v", err))
	} else {
		c.nodeInfoLabel.SetText(fmt.Sprintf("当前节点: %s\n延迟: %d ms\n更新时间: %s",
			nodeInfo, delay, time.Now().Format("15:04:05")))
	}
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	c.memoryLabel.SetText(fmt.Sprintf("内存使用: %s / %s\n更新时间: %s",
		formatBytes(memStats.Alloc),
		formatBytes(memStats.Sys),
		time.Now().Format("15:04:05")))
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (c *ClashController) getActiveNode() (string, int, error) {
	resp, err := http.Get("http://127.0.0.1:9090/proxies/亚洲负载均衡")
	if err != nil {
		return "", 0, fmt.Errorf("API请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("API返回错误: %s", resp.Status)
	}

	var data Proxy
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", 0, fmt.Errorf("解析响应失败: %v", err)
	}

	if data.Now == "" {
		return "未选择节点", 0, nil
	}

	var proxyNode ProxyNode
	encodedNode := url.PathEscape(data.Now)
	respproxy, err := http.Get("http://127.0.0.1:9090/proxies/" + encodedNode)
	if err != nil {
		return data.Now, 0, fmt.Errorf("获取节点延迟失败: %v", err)
	}
	defer respproxy.Body.Close()

	if err := json.NewDecoder(respproxy.Body).Decode(&proxyNode); err != nil {
		return data.Now, 0, fmt.Errorf("解析节点延迟失败: %v", err)
	}

	if len(proxyNode.History) > 0 {
		return data.Now, proxyNode.History[len(proxyNode.History)-1].Delay, nil
	}
	return data.Now, 0, nil
}

func (c *ClashController) stopClash() {
	c.statusLabel.SetText("状态: 停止中...")
	c.controlBtn.Disable()
	c.nodeInfoLabel.SetText("当前节点: 停止中...")
	c.memoryLabel.SetText("内存: 停止中...")

	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		if c.clashCmd == nil || c.clashCmd.Process == nil {
			c.running = false
			c.statusLabel.SetText("状态: 代理未运行")
			c.controlBtn.SetText("启动代理")
			c.controlBtn.Importance = widget.HighImportance
			c.controlBtn.Enable()
			c.nodeInfoLabel.SetText("当前节点: 未运行")
			c.memoryLabel.SetText("内存: -")
			return
		}

		close(c.stopMonitor)
		c.stopMonitor = make(chan struct{})

		if err := terminateProcessTree(c.clashCmd.Process); err != nil {
			c.nodeInfoLabel.SetText("停止失败: " + err.Error())
		} else {
			c.running = false
			c.statusLabel.SetText("状态: 代理已停止")
			c.controlBtn.SetText("启动代理")
			c.controlBtn.Importance = widget.HighImportance
			c.nodeInfoLabel.SetText("当前节点: 代理已停止")
			c.memoryLabel.SetText("内存: 代理已停止")
			c.clashCmd = nil
		}

		c.controlBtn.Enable()
	}()
}

func terminateProcessTree(process *os.Process) error {
	if process == nil {
		return nil
	}

	cmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", process.Pid))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("taskkill失败: %v", err)
	}
	return nil
}

func (c *ClashController) checkSystemProxy() {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.READ)
	if err != nil {
		c.proxyStatusLbl.SetText("系统代理状态: 检测失败")
		return
	}
	defer key.Close()

	enable, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil {
		c.proxyStatusLbl.SetText("系统代理状态: 检测失败")
		return
	}

	proxyServer, _, err := key.GetStringValue("ProxyServer")
	if err != nil && err != registry.ErrNotExist {
		c.proxyStatusLbl.SetText("系统代理状态: 检测失败")
		return
	}

	c.proxyStatus = enable != 0
	if c.proxyStatus {
		c.proxyStatusLbl.SetText(fmt.Sprintf("系统代理状态: 已启用 (%s)", proxyServer))
		c.proxyToggleBtn.SetText("关闭系统代理")
		c.proxyToggleBtn.Importance = widget.DangerImportance
	} else {
		c.proxyStatusLbl.SetText("系统代理状态: 已禁用")
		c.proxyToggleBtn.SetText("启用系统代理")
		c.proxyToggleBtn.Importance = widget.HighImportance
	}
}

func (c *ClashController) toggleSystemProxy() {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.WRITE)
	if err != nil {
		dialog.ShowError(fmt.Errorf("无法访问注册表: %v", err), c.window)
		return
	}
	defer key.Close()

	if c.proxyStatus {
		if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
			dialog.ShowError(fmt.Errorf("禁用代理失败: %v", err), c.window)
			return
		}
		c.proxyStatus = false
		c.proxyStatusLbl.SetText("系统代理状态: 已禁用")
		c.proxyToggleBtn.SetText("启用系统代理")
		c.proxyToggleBtn.Importance = widget.HighImportance
	} else {
		if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
			dialog.ShowError(fmt.Errorf("启用代理失败: %v", err), c.window)
			return
		}
		if err := key.SetStringValue("ProxyServer", "127.0.0.1:7890"); err != nil {
			dialog.ShowError(fmt.Errorf("设置代理地址失败: %v", err), c.window)
			return
		}
		c.proxyStatus = true
		c.proxyStatusLbl.SetText("系统代理状态: 已启用")
		c.proxyToggleBtn.SetText("关闭系统代理")
		c.proxyToggleBtn.Importance = widget.DangerImportance
	}

	syscallMessage()
	dialog.ShowInformation("成功", "系统代理设置已更新", c.window)
}

func syscallMessage() {
	const (
		SMTO_ABORTIFHUNG = 0x0002
		WM_SETTINGCHANGE = 0x001A
		HWND_BROADCAST   = 0xFFFF
	)

	user32 := windows.NewLazySystemDLL("user32.dll")
	sendMessageTimeout := user32.NewProc("SendMessageTimeoutW")

	setting, _ := windows.UTF16PtrFromString("Internet Settings")

	sendMessageTimeout.Call(
		uintptr(HWND_BROADCAST),
		uintptr(WM_SETTINGCHANGE),
		0,
		uintptr(unsafe.Pointer(setting)),
		uintptr(SMTO_ABORTIFHUNG),
		uintptr(1000),
		0,
	)
}

func (c *ClashController) updateRemoteConfig() {
	dialogTitle := "更新远程配置"
	input := widget.NewEntry()
	input.SetPlaceHolder("输入Clash配置URL (http://...)")
	if c.subscriptionURL != "" {
		input.SetText(c.subscriptionURL)
	}

	inputContainer := container.NewVBox(input)

	var d dialog.Dialog

	confirmBtn := widget.NewButton("下载", func() {
		urlStr := strings.TrimSpace(input.Text)
		if urlStr == "" {
			dialog.ShowError(fmt.Errorf("请输入有效的URL"), c.window)
			return
		}

		c.subscriptionURL = urlStr
		c.downloadConfig(urlStr, false)
		d.Hide()
	})
	cancelBtn := widget.NewButton("取消", func() {
		d.Hide()
	})

	buttons := container.NewHBox(layout.NewSpacer(), cancelBtn, confirmBtn)

	content := container.NewVBox(
		widget.NewLabel("输入配置URL:"),
		widget.NewLabel(fmt.Sprintf("设备ID: %s 将作为参数发送", c.deviceID)),
		inputContainer,
		buttons,
	)

	d = dialog.NewCustom(dialogTitle, "关闭", content, c.window)
	d.Resize(fyne.NewSize(400, 180))
	d.Show()
}

func (c *ClashController) downloadConfig(url string, autoUpdate bool) {
	if url == "" {
		if !autoUpdate {
			dialog.ShowError(fmt.Errorf("订阅URL不能为空"), c.window)
		}
		return
	}

	progress := widget.NewProgressBarInfinite()
	title := "正在下载配置"
	if autoUpdate {
		title = "正在自动更新配置"
	}
	d := dialog.NewCustom(title, "取消", progress, c.window)
	d.Show()

	go func() {
		if !strings.Contains(url, "?") {
			url += "?"
		} else {
			url += "&"
		}
		url += "device_id=" + c.deviceID
		// url.QueryEscape()

		resp, err := http.Get(url)
		if err != nil {
			d.Hide()
			if !autoUpdate {
				dialog.ShowError(fmt.Errorf("下载失败: %v", err), c.window)
			}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			d.Hide()
			if !autoUpdate {
				dialog.ShowError(fmt.Errorf("服务器返回错误: %s", resp.Status), c.window)
			}
			return
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			d.Hide()
			if !autoUpdate {
				dialog.ShowError(fmt.Errorf("读取数据失败: %v", err), c.window)
			}
			return
		}

		if err := ioutil.WriteFile(c.configPath, data, 0644); err != nil {
			d.Hide()
			if !autoUpdate {
				dialog.ShowError(fmt.Errorf("保存配置失败: %v", err), c.window)
			}
			return
		}

		d.Hide()
		if !autoUpdate {
			dialog.ShowInformation("成功", "配置已更新", c.window)
		}

		if c.running {
			if !autoUpdate {
				dialog.ShowConfirm("重启代理", "配置已更改，是否立即重启代理？", func(ok bool) {
					if ok {
						c.stopClash()
						time.Sleep(1 * time.Second)
						c.startClash()
					}
				}, c.window)
			} else {
				c.stopClash()
				time.Sleep(1 * time.Second)
				c.startClash()
			}
		}
	}()
}

func (c *ClashController) exitApplication(settingsPath string) {
	c.stopClash()
	c.stopAutoUpdate()
	c.saveSettings(settingsPath)

	if c.proxyStatus {
		c.toggleSystemProxy()
	}

	c.window.Close()
}
