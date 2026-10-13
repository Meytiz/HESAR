//go:build linux

package provision

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Meytiz/HESAR/backend/internal/config"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed layer3_helper.py
var helperFS embed.FS
var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type coreEntry struct {
	cfg           *config.TunnelConfig
	effective     *config.TunnelConfig
	dir           string
	l3            bool
	rules         [][]string
	process       *exec.Cmd
	done          chan error
	recoveryError string
}
type agent struct {
	mu                   sync.Mutex
	entries              map[string]*coreEntry
	state, cores, helper string
	uid, gid             uint32
}
type authorizedListener struct {
	net.Listener
	uid uint32
}

func (l authorizedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		u, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		raw, err := u.SyscallConn()
		allowed := false
		if err == nil {
			_ = raw.Control(func(fd uintptr) {
				cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				allowed = e == nil && (cred.Uid == l.uid || cred.Uid == 0)
			})
		}
		if allowed {
			return c, nil
		}
		c.Close()
	}
}
func ServeAgent(ctx context.Context, socket, state, cores string, uid, gid uint32) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("network agent must run as root")
	}
	if err := os.MkdirAll(state, 0750); err != nil {
		return err
	}
	if err := os.Chown(state, 0, int(gid)); err != nil {
		return err
	}
	a := &agent{entries: map[string]*coreEntry{}, state: state, cores: cores, uid: uid, gid: gid, helper: filepath.Join(state, "layer3_helper.py")}
	helper, err := helperFS.ReadFile("layer3_helper.py")
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.helper, helper, 0600); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(state, "tuning-enabled")); err == nil {
		_ = a.optimize()
	}
	// Recover only registry entries written in this root-owned directory.
	dirs, _ := os.ReadDir(state)
	for _, dir := range dirs {
		if !dir.IsDir() || !strings.HasPrefix(dir.Name(), "t-") {
			continue
		}
		path := filepath.Join(state, dir.Name())
		data, e := os.ReadFile(filepath.Join(path, "request.json"))
		if e != nil {
			continue
		}
		var c config.TunnelConfig
		if json.Unmarshal(data, &c) != nil || !safeID.MatchString(c.ID) || config.ValidateTunnel(&c) != nil || dir.Name() != entryName(c.ID) {
			return fmt.Errorf("invalid persisted agent registry")
		}
		entry, e := a.describe(&c, path)
		if e != nil {
			return e
		}
		if e = a.cleanup(entry); e != nil {
			entry.recoveryError = e.Error()
			a.entries[c.ID] = entry
			fmt.Fprintln(os.Stderr, "managed recovery pending:", c.ID, e)
		}
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0750); err != nil {
		return err
	}
	if err := os.Chown(filepath.Dir(socket), 0, int(gid)); err != nil {
		return err
	}
	if old, e := os.Lstat(socket); e == nil {
		if old.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("control path is not a socket")
		}
		if c, e := net.DialTimeout("unix", socket, time.Second); e == nil {
			c.Close()
			return fmt.Errorf("another network agent is running")
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0660); err != nil {
		return err
	}
	if err := os.Chown(socket, 0, int(gid)); err != nil {
		return err
	}
	if err := notifyReady(); err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(a.handle)}
	go func() { <-ctx.Done(); _ = server.Close() }()
	err = server.Serve(authorizedListener{listener, uid})
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if cleanupErr := a.cleanup(e); cleanupErr != nil {
			fmt.Fprintln(os.Stderr, "managed cleanup:", cleanupErr)
		}
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func notifyReady() error {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return nil
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("systemd readiness notification: %w", err)
	}
	defer connection.Close()
	_, err = connection.Write([]byte("READY=1\nSTATUS=Local network socket ready"))
	return err
}
func entryName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "t-" + hex.EncodeToString(sum[:10])
}
func (a *agent) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	write := func(reply Reply, status int) { w.WriteHeader(status); _ = json.NewEncoder(w).Encode(reply) }
	if r.Method != http.MethodPost {
		write(Reply{Error: "POST required"}, 405)
		return
	}
	var request Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		write(Reply{Error: "invalid request"}, 400)
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		write(Reply{Error: "trailing JSON"}, 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch r.URL.Path {
	case "/v1/optimize":
		reply := a.optimize()
		if err := a.write(a.state, "tuning-enabled", []byte("1\n"), false); err != nil {
			reply.Warnings = append(reply.Warnings, "Could not persist tuning preference")
		}
		write(reply, 200)
	case "/v1/status":
		reply := Reply{Available: true, Runtimes: []Runtime{}}
		for id, e := range a.entries {
			running := true
			if e.recoveryError != "" {
				running = false
			}
			if e.l3 {
				iface, err := net.InterfaceByName(e.effective.UnderlayInterface)
				if err != nil || iface.Flags&net.FlagUp == 0 {
					running = false
				}
			}
			if e.done != nil {
				select {
				case err := <-e.done:
					e.done <- err
					running = false
				default:
				}
			}
			reply.Runtimes = append(reply.Runtimes, Runtime{ID: id, Carrier: e.cfg.Carrier, Running: running, Error: e.recoveryError})
		}
		write(reply, 200)
	case "/v1/release":
		if !safeID.MatchString(request.ID) {
			write(Reply{Error: "invalid ID"}, 400)
			return
		}
		if e := a.entries[request.ID]; e != nil {
			if err := a.cleanup(e); err != nil {
				write(Reply{Error: err.Error()}, 500)
				return
			}
			delete(a.entries, request.ID)
		}
		write(Reply{Available: true}, 200)
	case "/v1/ensure":
		c := request.Tunnel
		if c == nil || !safeID.MatchString(c.ID) {
			write(Reply{Error: "invalid tunnel"}, 400)
			return
		}
		if err := config.ValidateTunnel(c); err != nil {
			write(Reply{Error: err.Error()}, 400)
			return
		}
		if c.Carrier == "" {
			c.Carrier = "direct"
		}
		if e := a.entries[c.ID]; e != nil {
			if err := a.cleanup(e); err != nil {
				write(Reply{Error: err.Error()}, 500)
				return
			}
			delete(a.entries, c.ID)
		}
		if len(a.entries) >= 16 {
			write(Reply{Error: "managed transport limit (16) reached"}, 409)
			return
		}
		for _, e := range a.entries {
			if c.Mode == "overseas" && e.cfg.Mode == "overseas" && c.Carrier != "gre" && c.Carrier != "ipip" && c.Carrier != "direct" && e.cfg.Carrier != "direct" && c.CarrierPort == e.cfg.CarrierPort {
				write(Reply{Error: "carrier port already reserved by another managed tunnel"}, 409)
				return
			}
		}
		e, err := a.ensure(c)
		if err != nil {
			write(Reply{Error: err.Error()}, 400)
			return
		}
		a.entries[c.ID] = e
		write(Reply{Available: true, Tunnel: e.effective}, 200)
	default:
		write(Reply{Error: "unknown operation"}, 404)
	}
}
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s operation failed: %s", name, strings.TrimSpace(string(data)))
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("operation output exceeded limit")
	}
	return data, nil
}
func (a *agent) network(c *config.TunnelConfig) (local, device, next string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer := c.CarrierPeerIP
	if c.Carrier == "direct" && peer == "" {
		peer = c.RemoteIP
		if p := net.ParseIP(peer); p == nil || p.To4() == nil || p.IsLoopback() {
			peer = "1.1.1.1"
		}
	}
	data, err := command(ctx, "ip", "-j", "-4", "route", "get", peer)
	if err != nil {
		return "", "", "", err
	}
	var routes []struct {
		Dev     string `json:"dev"`
		Source  string `json:"prefsrc"`
		Gateway string `json:"gateway"`
	}
	if json.Unmarshal(data, &routes) != nil || len(routes) != 1 {
		return "", "", "", fmt.Errorf("cannot discover WAN route")
	}
	local, device, next = routes[0].Source, routes[0].Dev, routes[0].Gateway
	if c.CarrierLocalIP != "" {
		local = c.CarrierLocalIP
	}
	if next == "" {
		next = c.CarrierPeerIP
	}
	iface, err := net.InterfaceByName(device)
	if err != nil || iface.Flags&net.FlagUp == 0 || device == "lo" {
		return "", "", "", fmt.Errorf("WAN route has no usable interface")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return "", "", "", err
	}
	assigned := false
	for _, address := range addresses {
		p, _, e := net.ParseCIDR(address.String())
		if e == nil && p.Equal(net.ParseIP(local)) {
			assigned = true
		}
	}
	if !assigned {
		return "", "", "", fmt.Errorf("WAN IPv4 is not assigned to the discovered interface")
	}
	return
}
func (a *agent) describe(c *config.TunnelConfig, dir string) (*coreEntry, error) {
	copy := *c
	copy.Carrier = ""
	copy.NetworkProfile = "custom"
	e := &coreEntry{cfg: c, effective: &copy, dir: dir}
	// Firewall state is written before insertion and recovered exactly, including
	// ephemeral proxy ports. It lives in a root-owned, non-writable registry.
	if data, err := os.ReadFile(filepath.Join(dir, "firewall.json")); err == nil {
		if len(data) > 65536 || json.Unmarshal(data, &e.rules) != nil || len(e.rules) > 64 {
			return nil, fmt.Errorf("invalid persisted firewall state")
		}
	}
	if c.Carrier == "direct" {
		return e, nil
	}
	if c.Carrier == "gre" || c.Carrier == "ipip" {
		e.l3 = true
		sum := sha256.Sum256([]byte(c.ID))
		copy.UnderlayInterface = "hsl3-" + hex.EncodeToString(sum[:5])
		copy.ProxyURL = ""
		copy.QUICDisablePMTU = true
		if c.Mode == "iran" {
			copy.RemoteIP = c.CarrierRemoteInner
		} else {
			copy.ListenAddress = c.CarrierLocalInner
		}
		return e, nil
	}
	copy.UnderlayInterface = ""
	copy.ListenAddress = "127.0.0.1"
	copy.RemoteIP = "127.0.0.1"
	if c.Carrier == "paqet" && c.Mode == "overseas" && len(e.rules) == 0 {
		// Comments distinguish only rules owned by this managed tunnel.
		local := c.CarrierLocalIP
		if local == "" {
			var err error
			local, _, _, err = a.network(c)
			if err != nil {
				return nil, err
			}
		}
		peer, port, tag := c.CarrierPeerIP, strconv.Itoa(c.CarrierPort), "hesar-"+entryName(c.ID)
		e.rules = [][]string{{"raw", "PREROUTING", "-s", peer, "-d", local, "-p", "tcp", "--dport", port, "-m", "comment", "--comment", tag, "-j", "NOTRACK"}, {"raw", "OUTPUT", "-s", local, "-d", peer, "-p", "tcp", "--sport", port, "-m", "comment", "--comment", tag, "-j", "NOTRACK"}, {"mangle", "OUTPUT", "-s", local, "-d", peer, "-p", "tcp", "--sport", port, "--tcp-flags", "RST", "RST", "-m", "comment", "--comment", tag, "-j", "DROP"}}
	}
	return e, nil
}
func (a *agent) write(dir, name string, data []byte, readable bool) error {
	mode := os.FileMode(0600)
	if readable {
		mode = 0640
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, mode); err != nil {
		return err
	}
	return os.Chown(p, 0, int(a.gid))
}
func (a *agent) ensure(c *config.TunnelConfig) (entry *coreEntry, returned error) {
	// Persist discovery so crash recovery does not depend on the old WAN route.
	local, device, next, err := a.network(c)
	if err != nil {
		return nil, err
	}
	copy := *c
	copy.CarrierLocalIP = local
	c = &copy
	dir := filepath.Join(a.state, entryName(c.ID))
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	if err := os.Chown(dir, 0, int(a.gid)); err != nil {
		return nil, err
	}
	e, err := a.describe(c, dir)
	if err != nil {
		return nil, err
	}
	persisted, _ := json.Marshal(c)
	if err := a.write(dir, "request.json", persisted, false); err != nil {
		return nil, err
	}
	defer func() {
		if returned != nil {
			if cleanupErr := a.cleanup(e); cleanupErr != nil {
				returned = fmt.Errorf("%w; cleanup incomplete: %v", returned, cleanupErr)
				a.entries[c.ID] = e
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e.l3 {
		sum := sha256.Sum256([]byte(c.ID))
		table := 10000 + (int(sum[5])<<8|int(sum[6]))%22000
		link := map[string]any{"interface": e.effective.UnderlayInterface, "mode": c.Carrier, "local_outer": local, "remote_outer": c.CarrierPeerIP, "local_inner": c.CarrierLocalInner, "remote_inner": c.CarrierRemoteInner, "mtu": c.CarrierMTU, "table": table, "priority": table}
		data, _ := json.Marshal(link)
		if err := a.write(dir, "link.json", data, false); err != nil {
			return nil, err
		}
		if _, err := command(ctx, "python3", a.helper, "up", "--config", filepath.Join(dir, "link.json")); err != nil {
			return nil, err
		}
		e.rules = append(e.rules, firewallRules(e, local, 0)...)
		if err := a.installFirewall(ctx, e); err != nil {
			return nil, err
		}
		if err := a.resolveTargets(ctx, e, local); err != nil {
			return nil, err
		}
		return e, nil
	}
	if c.Carrier == "direct" {
		e.rules = append(e.rules, firewallRules(e, local, 0)...)
		if err := a.installFirewall(ctx, e); err != nil {
			return nil, err
		}
		if err := a.resolveTargets(ctx, e, local); err != nil {
			return nil, err
		}
		return e, nil
	}
	socksPort := 0
	if c.Mode == "iran" {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		socksPort = l.Addr().(*net.TCPAddr).Port
		l.Close()
		e.effective.ProxyURL = "socks5://127.0.0.1:" + strconv.Itoa(socksPort)
	}
	mac := ""
	e.rules = append(e.rules, firewallRules(e, local, socksPort)...)
	if c.Carrier == "paqet" {
		e.rules = append(e.rules, neighborRules(e, local, device, next)...)
	}
	if err := a.installFirewall(ctx, e); err != nil {
		return nil, err
	}
	if err := a.resolveTargets(ctx, e, local); err != nil {
		return nil, err
	}
	if c.Carrier == "paqet" {
		_, _ = command(ctx, "ping", "-c", "1", "-W", "1", "-I", device, next)
		data, err := command(ctx, "ip", "-j", "neigh", "show", next, "dev", device)
		if err != nil {
			return nil, err
		}
		var neighbors []struct {
			MAC string `json:"lladdr"`
		}
		if json.Unmarshal(data, &neighbors) != nil || len(neighbors) != 1 {
			return nil, fmt.Errorf("next-hop MAC could not be discovered")
		}
		if _, err := net.ParseMAC(neighbors[0].MAC); err != nil {
			return nil, fmt.Errorf("next-hop neighbor has no valid MAC")
		}
		mac = neighbors[0].MAC
	}
	body, err := a.coreConfig(e, local, device, mac, socksPort)
	if err != nil {
		return nil, err
	}
	if err := a.write(dir, "core.json", body, true); err != nil {
		return nil, err
	}
	binary := filepath.Join(a.cores, c.Carrier)
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0022 != 0 {
		return nil, fmt.Errorf("packaged %s core is missing or writable by an untrusted account", c.Carrier)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, fmt.Errorf("packaged core must be root-owned")
	}
	args := []string{"run", "-c", filepath.Join(dir, "core.json")}
	if c.Carrier == "xray" {
		args = []string{"run", "-config", filepath.Join(dir, "core.json")}
	} else if c.Carrier == "hysteria" {
		role := "client"
		if c.Mode == "overseas" {
			role = "server"
		}
		args = []string{role, "-c", filepath.Join(dir, "core.json")}
	}
	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true, Credential: &syscall.Credential{Uid: a.uid, Gid: a.gid}}
	if c.Carrier == "paqet" {
		cmd.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_RAW, unix.CAP_NET_ADMIN}
	} else if c.Mode == "overseas" && c.CarrierPort < 1024 {
		cmd.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_BIND_SERVICE}
	}
	// Core diagnostics go to journald; generated secrets never appear in argv.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start packaged core: %w", err)
	}
	e.process = cmd
	e.done = make(chan error, 1)
	go func() { e.done <- cmd.Wait() }()
	timer := time.NewTimer(600 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case err := <-e.done:
		e.done <- err
		return nil, fmt.Errorf("packaged core exited during startup; inspect agent journal")
	}
	if c.Mode == "iran" {
		deadline := time.Now().Add(3 * time.Second)
		for {
			connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 200*time.Millisecond)
			if err == nil {
				connection.Close()
				break
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("packaged core did not open its private proxy")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return e, nil
}
func (a *agent) cleanup(e *coreEntry) error {
	if e.process != nil {
		_ = e.process.Process.Signal(syscall.SIGTERM)
		select {
		case <-e.done:
		case <-time.After(3 * time.Second):
			_ = e.process.Process.Kill()
			<-e.done
		}
		e.process = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e.l3 {
		// Failed preflight has no marker: preserve the foreign link/table.
		if _, err := os.Stat(filepath.Join(e.dir, "link-owned")); err == nil {
			if _, err := command(ctx, "python3", a.helper, "down", "--config", filepath.Join(e.dir, "link.json")); err != nil {
				return err
			}
		}
	}
	for _, rule := range e.rules {
		exists, err := firewallRuleExists(ctx, rule)
		if err != nil {
			return err
		}
		if exists {
			if _, err := command(ctx, "iptables", firewallArgs(rule, "-D")...); err != nil {
				return err
			}
		}
	}
	return os.RemoveAll(e.dir) // dir is a hash-derived child of a root-owned registry.
}
