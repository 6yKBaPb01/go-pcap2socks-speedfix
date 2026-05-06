package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"path"
	"runtime"

	"github.com/fsnotify/fsnotify"

	"github.com/DaniilSokolyuk/go-pcap2socks/cfg"
	"github.com/DaniilSokolyuk/go-pcap2socks/core"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/device"
	"github.com/DaniilSokolyuk/go-pcap2socks/core/option"
	"github.com/DaniilSokolyuk/go-pcap2socks/proxy"
	"github.com/jackpal/gateway" 
	"gvisor.dev/gvisor/pkg/tcpip"
    "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

//go:embed config.json
var configData string

var (
    _defaultDevice device.Device
    _defaultStack  *stack.Stack
    _currentCfg    *cfg.Config
)

func main() {
	logLevel := slog.LevelInfo
	if lvl := os.Getenv("SLOG_LEVEL"); lvl != "" {
		switch lvl {
		case "debug", "DEBUG":
			logLevel = slog.LevelDebug
		case "info", "INFO":
			logLevel = slog.LevelInfo
		case "warn", "WARN":
			logLevel = slog.LevelWarn
		case "error", "ERROR":
			logLevel = slog.LevelError
		}
	}
	opts := &slog.HandlerOptions{Level: logLevel}
	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))

	if len(os.Args) > 1 && os.Args[1] == "config" {
		openConfigInEditor()
		return
	}

	cfgFile := resolveConfigPath()
	if !cfg.Exists(cfgFile) {
		slog.Info("Config file not found, creating a new one", "file", cfgFile)
		if err := os.WriteFile(cfgFile, []byte(configData), 0666); err != nil {
			slog.Error("write config error", slog.Any("file", cfgFile), slog.Any("err", err))
			return
		}
	}

	config, err := cfg.Load(cfgFile)
	if err != nil {
		slog.Error("load config error", slog.Any("file", cfgFile), slog.Any("err", err))
		return
	}
	slog.Info("Config loaded", "file", cfgFile)

	executeOnStart(config)

	if err = run(config); err != nil {
		slog.Error("run error", slog.Any("err", err))
		return
	}

	go watchConfig(cfgFile)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello world!"))
	})
	log.Fatal(http.ListenAndServe(":8085", nil))
}

func resolveConfigPath() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	exe, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	return path.Join(path.Dir(exe), "config.json")
}

func executeOnStart(cfg *cfg.Config) {
	if len(cfg.ExecuteOnStart) == 0 {
		return
	}
	slog.Info("Executing commands on start", "cmd", cfg.ExecuteOnStart)
	var cmd *exec.Cmd
	if len(cfg.ExecuteOnStart) > 1 {
		cmd = exec.Command(cfg.ExecuteOnStart[0], cfg.ExecuteOnStart[1:]...)
	} else {
		cmd = exec.Command(cfg.ExecuteOnStart[0])
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	go func() {
		if err := cmd.Start(); err != nil {
			slog.Error("execute command error", slog.Any("err", err))
			return
		}
		_ = cmd.Wait()
	}()
}

func run(cfg *cfg.Config) error {
	ifce := findInterface(cfg.PCAP.InterfaceGateway)
	slog.Info("Using ethernet interface", "interface", ifce.Name, "mac", ifce.HardwareAddr.String())

	netConfig, err := parseNetworkConfig(cfg.PCAP, ifce)
	if err != nil {
		return err
	}
	displayNetworkConfig(netConfig)

	proxies := make(map[string]proxy.Proxy)
	for _, out := range cfg.Outbounds {
		var p proxy.Proxy
		switch {
		case out.Direct != nil:
			p = proxy.NewDirect()
		case out.Socks != nil:
			p, err = proxy.NewSocks5(out.Socks.Address, out.Socks.Username, out.Socks.Password)
			if err != nil {
				return fmt.Errorf("new socks5 error: %w", err)
			}
		case out.Reject != nil:
			p = proxy.NewReject()
		case out.DNS != nil:
			p = proxy.NewDNS(cfg.DNS, ifce.Name)
		default:
			return fmt.Errorf("invalid outbound: %+v", out)
		}
		proxies[out.Tag] = p
	}

	router := proxy.NewRouter(cfg.Routing.Rules, proxies)
	proxy.SetDialer(router)

	dev, err := device.Open(cfg.Capture, ifce, netConfig, func() device.Stacker {
		return _defaultStack
	})
	if err != nil {
		return err
	}
	_defaultDevice = dev

	stack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     _defaultDevice,
		TransportHandler: &core.Tunnel{},
		MulticastGroups:  []net.IP{},
		Options:          []option.Option{},
	})
	if err != nil {
		return fmt.Errorf("create stack: %w", err)
	}
	_defaultStack = stack

	recoveryOpt := tcpip.TCPRecovery(0)
	if err := _defaultStack.SetTransportProtocolOption(tcp.ProtocolNumber, &recoveryOpt); err != nil {
    return fmt.Errorf("failed to disable RACK: %w", err)
}

	sackOpt := tcpip.TCPSACKEnabled(false)
	if err := _defaultStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); err != nil {
    return fmt.Errorf("failed to disable SACK: %w", err)
}

	_currentCfg = cfg
	return nil
}

// ---------- hot reload ----------

func watchConfig(cfgFile string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("create fsnotify watcher error", slog.Any("err", err))
		return
	}
	defer watcher.Close()

	if err := watcher.Add(cfgFile); err != nil {
		slog.Error("watch config file error", slog.Any("file", cfgFile), slog.Any("err", err))
		return
	}
	slog.Info("Watching config file for changes", "file", cfgFile)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				slog.Info("Config file changed, reloading...", "file", cfgFile)
				newCfg, err := cfg.Load(cfgFile)
				if err != nil {
					slog.Error("reload config error", slog.Any("err", err))
					continue
				}
				applyHotReload(newCfg)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Error("fsnotify error", slog.Any("err", err))
		}
	}
}

func applyHotReload(newCfg *cfg.Config) {
	if _currentCfg == nil {
		return
	}

	// 1. Если изменились только прокси-правила, меняем dialer бесшовно
	oldProxyHash := hashProxySection(_currentCfg)
	newProxyHash := hashProxySection(newCfg)
	if oldProxyHash != newProxyHash {
		slog.Info("Proxy section changed, hot-swapping dialer...")
		router, err := buildRouter(newCfg)
		if err != nil {
			slog.Error("failed to build new router", slog.Any("err", err))
			return
		}
		proxy.SetDialer(router)
		slog.Info("Dialer hot-swapped successfully")
	}

	// 2. Если изменились сетевые параметры — полный перезапуск стека
	if newCfg.PCAP.Network != _currentCfg.PCAP.Network ||
		newCfg.PCAP.LocalIP != _currentCfg.PCAP.LocalIP ||
		newCfg.PCAP.MTU != _currentCfg.PCAP.MTU {
		slog.Info("Network/PCAP settings changed, performing full restart...")
		if err := restartStack(newCfg); err != nil {
			slog.Error("full restart failed", slog.Any("err", err))
			return
		}
		slog.Info("Full restart completed")
	}

	_currentCfg = newCfg
}

func hashProxySection(cfg *cfg.Config) string {
	h := sha256.New()
	for _, out := range cfg.Outbounds {
		fmt.Fprintf(h, "%+v", out)
	}
	for _, rule := range cfg.Routing.Rules {
		fmt.Fprintf(h, "%+v", rule)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func buildRouter(cfg *cfg.Config) (proxy.Proxy, error) {
	proxies := make(map[string]proxy.Proxy)
	for _, out := range cfg.Outbounds {
		var p proxy.Proxy
		var err error
		switch {
		case out.Direct != nil:
			p = proxy.NewDirect()
		case out.Socks != nil:
			p, err = proxy.NewSocks5(out.Socks.Address, out.Socks.Username, out.Socks.Password)
			if err != nil {
				return nil, fmt.Errorf("new socks5 error: %w", err)
			}
		case out.Reject != nil:
			p = proxy.NewReject()
		case out.DNS != nil:
			p = proxy.NewDNS(cfg.DNS, "")
		default:
			return nil, fmt.Errorf("invalid outbound: %+v", out)
		}
		proxies[out.Tag] = p
	}
	return proxy.NewRouter(cfg.Routing.Rules, proxies), nil
}

func restartStack(cfg *cfg.Config) error {
	// 1. Закрываем старые
	if _defaultStack != nil {
		_defaultStack.Close()
		_defaultStack = nil
	}
	if _defaultDevice != nil {
		_defaultDevice.Close()
		_defaultDevice = nil
	}

	// 2. Находим интерфейс заново
	ifce := findInterface(cfg.PCAP.InterfaceGateway)
	netConfig, err := parseNetworkConfig(cfg.PCAP, ifce)
	if err != nil {
		return fmt.Errorf("parse network config: %w", err)
	}

	// 3. Создаём устройство и стек
	dev, err := device.Open(cfg.Capture, ifce, netConfig, func() device.Stacker {
		return _defaultStack
	})
	if err != nil {
		return fmt.Errorf("open device: %w", err)
	}
	_defaultDevice = dev

	stack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     _defaultDevice,
		TransportHandler: &core.Tunnel{},
		MulticastGroups:  []net.IP{},
		Options:          []option.Option{},
	})
	if err != nil {
		return fmt.Errorf("create stack: %w", err)
	}
	_defaultStack = stack
	return nil
}

// ---------- всё остальное без изменений ----------
// (findInterface, parseNetworkConfig, displayNetworkConfig, calculateIPRange, calculateRecommendedMTU, openConfigInEditor)

func findInterface(cfgIfce string) net.Interface {
    var targetIP net.IP
    if cfgIfce != "" {
        targetIP = net.ParseIP(cfgIfce)
        if targetIP == nil {
            panic(fmt.Errorf("parse ip error: %s", cfgIfce))
        }
    } else {
        var err error
        targetIP, err = gateway.DiscoverInterface()
        if err != nil {
            panic(fmt.Errorf("discover interface error: %w", err))
        }
    }
    ifaces, err := net.Interfaces()
    if err != nil {
        panic(err)
    }
    for _, iface := range ifaces {
        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }
        for _, addr := range addrs {
            ipnet, ok := addr.(*net.IPNet)
            if !ok {
                continue
            }
            ip4 := ipnet.IP.To4()
            if ip4 != nil && bytes.Equal(ip4, targetIP.To4()) {
                return iface
            }
        }
    }
    panic(fmt.Errorf("interface with IP %s not found", targetIP))
}

func parseNetworkConfig(pcapCfg cfg.PCAP, ifce net.Interface) (*device.NetworkConfig, error) {
    _, network, err := net.ParseCIDR(pcapCfg.Network)
    if err != nil {
        return nil, fmt.Errorf("parse cidr error: %w", err)
    }
    localIP := net.ParseIP(pcapCfg.LocalIP)
    if localIP == nil {
        return nil, fmt.Errorf("parse local ip error: %s", pcapCfg.LocalIP)
    }
    localIP = localIP.To4()
    if !network.Contains(localIP) {
        return nil, fmt.Errorf("local ip (%s) not in network (%s)", localIP, network)
    }
    var localMAC net.HardwareAddr
    if pcapCfg.LocalMAC != "" {
        localMAC, err = net.ParseMAC(pcapCfg.LocalMAC)
        if err != nil {
            return nil, fmt.Errorf("parse local mac error: %w", err)
        }
    } else {
        localMAC = ifce.HardwareAddr
    }
    mtu := pcapCfg.MTU
    if mtu == 0 {
        mtu = uint32(ifce.MTU)
    }
    return &device.NetworkConfig{
        Network:  network,
        LocalIP:  localIP,
        LocalMAC: localMAC,
        MTU:      mtu,
    }, nil
}

func displayNetworkConfig(config *device.NetworkConfig) {
    ipRangeStart, ipRangeEnd := calculateIPRange(config.Network, config.LocalIP)
    recommendedMTU := calculateRecommendedMTU(config.MTU)
    slog.Info("Configure your device with these network settings:")
    slog.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    slog.Info(fmt.Sprintf("  IP Address:     %s - %s", ipRangeStart.String(), ipRangeEnd.String()))
    slog.Info(fmt.Sprintf("  Subnet Mask:    %s", net.IP(config.Network.Mask).String()))
    slog.Info(fmt.Sprintf("  Gateway:        %s", config.LocalIP.String()))
    slog.Info(fmt.Sprintf("  MTU:            %d (or lower)", recommendedMTU))
    slog.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func calculateIPRange(network *net.IPNet, gatewayIP net.IP) (start, end net.IP) {
    networkIP := network.IP.To4()
    start = make(net.IP, 4)
    end = make(net.IP, 4)
    ones, bits := network.Mask.Size()
    hostBits := uint32(bits - ones)
    numHosts := (uint32(1) << hostBits) - 2

    binary.BigEndian.PutUint32(start, binary.BigEndian.Uint32(networkIP)+1)
    broadcastInt := binary.BigEndian.Uint32(networkIP) | ((1 << hostBits) - 1)
    binary.BigEndian.PutUint32(end, broadcastInt-1)

    if bytes.Equal(start, gatewayIP) && numHosts > 1 {
        binary.BigEndian.PutUint32(start, binary.BigEndian.Uint32(start)+1)
    } else if bytes.Equal(end, gatewayIP) && numHosts > 1 {
        binary.BigEndian.PutUint32(end, binary.BigEndian.Uint32(end)-1)
    }
    return start, end
}

func calculateRecommendedMTU(mtu uint32) uint32 {
    const ethernetHeaderSize = 14
    return mtu - ethernetHeaderSize
}

func openConfigInEditor() {
    executable, err := os.Executable()
    if err != nil {
        slog.Error("get executable error", slog.Any("err", err))
        return
    }
    cfgFile := path.Join(path.Dir(executable), "config.json")

    if !cfg.Exists(cfgFile) {
        slog.Info("Config file not found, creating a new one", "file", cfgFile)
        if err := os.WriteFile(cfgFile, []byte(configData), 0666); err != nil {
            slog.Error("write config error", slog.Any("file", cfgFile), slog.Any("err", err))
            return
        }
    }

    var cmd *exec.Cmd
    switch runtime.GOOS {
    case "windows":
        cmd = exec.Command("notepad", cfgFile)
    case "darwin":
        cmd = exec.Command("open", "-t", cfgFile)
    default:
        editor := os.Getenv("EDITOR")
        if editor == "" {
            editor = os.Getenv("VISUAL")
        }
        if editor == "" {
            editors := []string{"nano", "vim", "vi"}
            for _, e := range editors {
                if _, err := exec.LookPath(e); err == nil {
                    editor = e
                    break
                }
            }
        }
        if editor == "" {
            slog.Error("no editor found. Set EDITOR environment variable")
            return
        }
        cmd = exec.Command(editor, cfgFile)
    }

    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    slog.Info("Opening config in editor", "file", cfgFile)
    if err := cmd.Run(); err != nil {
        slog.Error("failed to open editor", slog.Any("err", err))
    }
}
