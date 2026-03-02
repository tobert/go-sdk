package sshtransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
)

// SSHHandlerOptions configures the SSH server handler.
type SSHHandlerOptions struct {
	// HostKey is the server's SSH host key. Required.
	HostKey ssh.Signer

	// AuthorizedKeys maps client public keys to identities and permissions.
	// At least one of AuthorizedKeys or TrustedCAs must be set.
	AuthorizedKeys *AuthorizedKeys

	// TrustedCAs are CA public keys for SSH certificate authentication.
	TrustedCAs []ssh.PublicKey

	// AcceptedPrincipals is the list of principals the server accepts
	// when verifying SSH certificates. Required if TrustedCAs is set.
	AcceptedPrincipals []string

	// Logger for SSH server events. Defaults to slog.Default().
	Logger *slog.Logger

	// MaxAuthRetries is the maximum number of authentication attempts per
	// connection. Default 6.
	MaxAuthRetries int

	// PreAuthTimeout is the deadline for completing authentication after
	// TCP connect. Default 30s.
	PreAuthTimeout time.Duration

	// Subsystems is the list of accepted subsystem names. Default ["mcp"].
	Subsystems []string
}

func (o *SSHHandlerOptions) logger() *slog.Logger {
	if o != nil && o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

func (o *SSHHandlerOptions) maxAuthRetries() int {
	if o != nil && o.MaxAuthRetries > 0 {
		return o.MaxAuthRetries
	}
	return 6
}

func (o *SSHHandlerOptions) preAuthTimeout() time.Duration {
	if o != nil && o.PreAuthTimeout > 0 {
		return o.PreAuthTimeout
	}
	return 30 * time.Second
}

func (o *SSHHandlerOptions) subsystems() []string {
	if o != nil && len(o.Subsystems) > 0 {
		return o.Subsystems
	}
	return []string{"mcp"}
}

func (o *SSHHandlerOptions) isSubsystem(name string) bool {
	for _, s := range o.subsystems() {
		if s == name {
			return true
		}
	}
	return false
}

// SSHHandler is an MCP-over-SSH server that accepts SSH connections and
// dispatches MCP sessions on subsystem channels.
type SSHHandler struct {
	getServer func() *mcp.Server
	opts      *SSHHandlerOptions
	config    *ssh.ServerConfig

	mu       sync.Mutex
	listener net.Listener
	sessions []*activeSession
	done     chan struct{}
}

type activeSession struct {
	ss     *mcp.ServerSession
	cancel context.CancelFunc
}

// NewSSHHandler creates a new SSH handler. getServer is called for each new
// MCP session to obtain the MCP server instance.
func NewSSHHandler(getServer func() *mcp.Server, opts *SSHHandlerOptions) *SSHHandler {
	h := &SSHHandler{
		getServer: getServer,
		opts:      opts,
		done:      make(chan struct{}),
	}

	config := &ssh.ServerConfig{
		MaxAuthTries:  opts.maxAuthRetries(),
		PublicKeyCallback: h.publicKeyCallback,
		// Disable other auth methods.
		NoClientAuth: false,
	}
	config.AddHostKey(opts.HostKey)
	h.config = config

	return h
}

// ListenAndServe starts the SSH server listening on the given address.
func (h *SSHHandler) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	return h.Serve(ctx, ln)
}

// Serve accepts SSH connections from the listener.
func (h *SSHHandler) Serve(ctx context.Context, ln net.Listener) error {
	h.mu.Lock()
	h.listener = ln
	h.mu.Unlock()

	logger := h.opts.logger()
	logger.Info("SSH server listening", "addr", ln.Addr())

	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-h.done:
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-h.done:
				return nil
			default:
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				logger.Error("accept error", "error", err)
				continue
			}
		}
		go h.handleConn(ctx, conn)
	}
}

// Close shuts down the SSH server and all active sessions.
func (h *SSHHandler) Close() error {
	close(h.done)
	h.mu.Lock()
	ln := h.listener
	sessions := h.sessions
	h.sessions = nil
	h.mu.Unlock()

	var errs []error
	if ln != nil {
		errs = append(errs, ln.Close())
	}
	for _, s := range sessions {
		s.cancel()
		errs = append(errs, s.ss.Close())
	}
	return errors.Join(errs...)
}

// Addr returns the listener's address, or "" if not listening.
func (h *SSHHandler) Addr() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.listener == nil {
		return ""
	}
	return h.listener.Addr().String()
}

func (h *SSHHandler) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	logger := h.opts.logger()

	var certPerm *Permission
	var keyPerm *Permission

	// Check certificates.
	if cert, ok := key.(*ssh.Certificate); ok && len(h.opts.TrustedCAs) > 0 {
		certChecker := &ssh.CertChecker{
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				for _, ca := range h.opts.TrustedCAs {
					if keysEqual(auth, ca) {
						return true
					}
				}
				return false
			},
		}
		if err := certChecker.CheckCert(conn.User(), cert); err != nil {
			logger.Warn("certificate validation failed", "user", conn.User(), "error", err)
			return nil, fmt.Errorf("certificate validation failed: %w", err)
		}
		if !h.matchesPrincipal(cert) {
			logger.Warn("no matching principal", "user", conn.User(), "principals", cert.ValidPrincipals)
			return nil, fmt.Errorf("no matching principal")
		}
		certPerm = PermissionsFromCertificate(cert)
	}

	// Check authorized keys (also for cert keys — the underlying public
	// key may have additional restrictions in authorized_keys).
	if h.opts.AuthorizedKeys != nil {
		lookupKey := key
		if cert, ok := key.(*ssh.Certificate); ok {
			lookupKey = cert.Key // use the underlying key, not the cert
		}
		fp := ssh.FingerprintSHA256(lookupKey)
		if perm, ok := h.opts.AuthorizedKeys.Lookup(fp); ok {
			logger.Info("key authenticated", "fingerprint", fp, "identity", perm.Identity)
			keyPerm = perm
		}
	}

	// Must have at least one auth method succeed.
	if certPerm == nil && keyPerm == nil {
		logger.Warn("authentication failed", "user", conn.User(), "key_type", key.Type())
		return nil, fmt.Errorf("unknown key")
	}

	return mergedPermToSSH(certPerm, keyPerm), nil
}

func (h *SSHHandler) matchesPrincipal(cert *ssh.Certificate) bool {
	for _, cp := range cert.ValidPrincipals {
		for _, ap := range h.opts.AcceptedPrincipals {
			if cp == ap {
				return true
			}
		}
	}
	return false
}

// mergedPermToSSH encodes cert and key permissions separately into
// ssh.Permissions.Extensions using prefixed keys. This preserves both
// sets for proper AND-logic checking on the other side.
func mergedPermToSSH(certPerm, keyPerm *Permission) *ssh.Permissions {
	ext := make(map[string]string)

	// Identity: prefer cert, fall back to key.
	if certPerm != nil && certPerm.Identity != "" {
		ext["identity"] = certPerm.Identity
	} else if keyPerm != nil {
		ext["identity"] = keyPerm.Identity
	}

	encodePerm := func(prefix string, perm *Permission) {
		if perm == nil {
			return
		}
		// Always encode all three fields when perm is non-nil so that
		// mergedPermFromSSH can distinguish "no auth" (no extensions) from
		// "auth with deny-all" (extensions present, null values).
		data, _ := json.Marshal(perm.RestrictTools)
		ext[prefix+"restrict-tools"] = string(data)
		data, _ = json.Marshal(perm.RestrictResources)
		ext[prefix+"restrict-resources"] = string(data)
		data, _ = json.Marshal(perm.RestrictPrompts)
		ext[prefix+"restrict-prompts"] = string(data)
	}

	encodePerm("cert-", certPerm)
	encodePerm("key-", keyPerm)

	return &ssh.Permissions{Extensions: ext}
}

// mergedPermFromSSH decodes a MergedPermission from ssh.Permissions.Extensions.
// Each side defaults to nil (deny). Fields are only set when the extension key
// is present AND the JSON unmarshals successfully — fail-closed on bad data.
func mergedPermFromSSH(sshPerm *ssh.Permissions) *MergedPermission {
	if sshPerm == nil {
		return &MergedPermission{}
	}

	decodePerm := func(prefix string) *Permission {
		// Check if any extensions exist for this prefix.
		hasTools := false
		hasResources := false
		hasPrompts := false
		var tools, resources, prompts []string

		if v, ok := sshPerm.Extensions[prefix+"restrict-tools"]; ok {
			hasTools = true
			json.Unmarshal([]byte(v), &tools) // nil on error = deny
		}
		if v, ok := sshPerm.Extensions[prefix+"restrict-resources"]; ok {
			hasResources = true
			json.Unmarshal([]byte(v), &resources)
		}
		if v, ok := sshPerm.Extensions[prefix+"restrict-prompts"]; ok {
			hasPrompts = true
			json.Unmarshal([]byte(v), &prompts)
		}

		// No extensions for this prefix → this auth method didn't match.
		if !hasTools && !hasResources && !hasPrompts {
			return nil
		}

		return &Permission{
			Identity:          sshPerm.Extensions["identity"],
			RestrictTools:     tools,
			RestrictResources: resources,
			RestrictPrompts:   prompts,
		}
	}

	return &MergedPermission{
		identity:  sshPerm.Extensions["identity"],
		CertPerms: decodePerm("cert-"),
		KeyPerms:  decodePerm("key-"),
	}
}

func (h *SSHHandler) handleConn(ctx context.Context, tcpConn net.Conn) {
	logger := h.opts.logger()

	// Pre-auth timeout.
	tcpConn.SetDeadline(time.Now().Add(h.opts.preAuthTimeout()))

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, h.config)
	if err != nil {
		logger.Debug("SSH handshake failed", "remote", tcpConn.RemoteAddr(), "error", err)
		tcpConn.Close()
		return
	}

	// Clear deadline after successful auth.
	tcpConn.SetDeadline(time.Time{})

	logger.Info("SSH connection established",
		"remote", sshConn.RemoteAddr(),
		"identity", sshConn.Permissions.Extensions["identity"],
	)

	// Discard global requests (keepalive responses are handled by the library).
	go ssh.DiscardRequests(reqs)

	perm := mergedPermFromSSH(sshConn.Permissions)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			logger.Error("channel accept error", "error", err)
			continue
		}

		go h.handleSession(ctx, ch, requests, perm, sshConn)
	}

	logger.Info("SSH connection closed", "remote", sshConn.RemoteAddr())
}

func (h *SSHHandler) handleSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, perm *MergedPermission, conn *ssh.ServerConn) {
	logger := h.opts.logger()

	for req := range reqs {
		switch req.Type {
		case "subsystem":
			subsystem := string(req.Payload[4:]) // SSH subsystem payload: uint32 length + name
			if !h.opts.isSubsystem(subsystem) {
				logger.Warn("rejected subsystem", "subsystem", subsystem)
				req.Reply(false, nil)
				ch.Close()
				return
			}

			req.Reply(true, nil)
			logger.Info("subsystem started", "subsystem", subsystem, "identity", perm.Identity())

			h.serveMCP(ctx, ch, perm)
			return

		case "shell", "exec", "pty-req", "x11-req", "auth-agent-req@openssh.com":
			logger.Warn("rejected channel request", "type", req.Type)
			if req.WantReply {
				req.Reply(false, nil)
			}
			ch.Close()
			return

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (h *SSHHandler) serveMCP(ctx context.Context, ch ssh.Channel, perm *MergedPermission) {
	logger := h.opts.logger()

	// Wrap SSH channel as MCP transport, injecting identity into requests.
	ioTransport := &mcp.IOTransport{
		Reader: io.NopCloser(ch),
		Writer: writeCloser{ch},
	}
	transport := &authTransport{inner: ioTransport, perm: perm}

	sessionCtx, cancel := context.WithCancel(ctx)
	sessionCtx = ContextWithPermissions(sessionCtx, perm)

	server := h.getServer()
	ss, err := server.Connect(sessionCtx, transport, nil)
	if err != nil {
		logger.Error("MCP connect error", "error", err, "identity", perm.Identity())
		cancel()
		ch.Close()
		return
	}

	h.mu.Lock()
	as := &activeSession{ss: ss, cancel: cancel}
	h.sessions = append(h.sessions, as)
	h.mu.Unlock()

	// Wait for session end.
	err = ss.Wait()
	if err != nil {
		logger.Debug("MCP session ended", "error", err, "identity", perm.Identity())
	} else {
		logger.Info("MCP session ended", "identity", perm.Identity())
	}

	cancel()
	ch.Close()

	h.mu.Lock()
	for i, s := range h.sessions {
		if s == as {
			h.sessions = append(h.sessions[:i], h.sessions[i+1:]...)
			break
		}
	}
	h.mu.Unlock()
}

// writeCloser wraps an ssh.Channel for IOTransport. We use the Channel's
// CloseWrite for Close so that the reader side gets EOF.
type writeCloser struct {
	ch ssh.Channel
}

func (w writeCloser) Write(p []byte) (int, error) { return w.ch.Write(p) }
func (w writeCloser) Close() error                { return w.ch.CloseWrite() }

// keysEqual compares two SSH public keys.
func keysEqual(a, b ssh.PublicKey) bool {
	return ssh.FingerprintSHA256(a) == ssh.FingerprintSHA256(b)
}
