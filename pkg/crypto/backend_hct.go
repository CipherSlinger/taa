package crypto

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"taa/internal/hctclient"
	"taa/internal/hctproto"
)

func init() {
	newHCTBackend = openHCTBackend
}

// hctChunkSize bounds one stream UPDATE frame. Splitting large files into
// frames keeps a single request small enough for a bounded timeout and lets
// concurrent streams interleave on the helper's single event loop.
const (
	hctChunkSize = 1 << 20
	// hctSM2PubSize is the x||y public key length libhct uses (no 0x04 prefix).
	hctSM2PubSize = 64
	// hctSM2SigSize is the r||s signature length libhct returns.
	hctSM2SigSize = 64
)

// hctBackend implements Backend on top of the long-lived helper process.
type hctBackend struct {
	client     *hctclient.Client
	nextStream atomic.Uint64
}

func openHCTBackend(cfg HCTConfig) (Backend, func() error, error) {
	requireVersion := cfg.RequireVersion
	if requireVersion == "" {
		requireVersion = HCTDefaultVersion
	}
	client, err := hctclient.Start(hctclient.Config{
		HelperPath:     cfg.HelperPath,
		LoaderPath:     cfg.LoaderPath,
		LibDir:         cfg.LibDir,
		Accel:          cfg.Accel,
		RequireVersion: requireVersion,
	})
	if err != nil {
		return nil, nil, err
	}
	b := &hctBackend{client: client}
	if err := runHCTKAT(b); err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("HCT 启动自检失败: %w", err)
	}
	return b, client.Close, nil
}

func (b *hctBackend) Name() string { return BackendHCT }

// Version reports the libhct version string the helper handshake returned.
func (b *hctBackend) Version() string { return b.client.Hello().Version }

// Accel reports the acceleration mode the helper actually started with. It can
// differ from the configured mode when the helper degrades.
func (b *hctBackend) Accel() string { return b.client.Hello().Accel }

// Engines reports which engine serves each operation group, as the helper
// reported it in the handshake.
func (b *hctBackend) Engines() string { return b.client.Hello().Engines }

func (b *hctBackend) Check(ctx context.Context) error {
	if err := b.client.Ping(ctx); err != nil {
		return wrapUnavailable(err)
	}
	return nil
}

// wrapUnavailable marks helper death as an availability failure the fallback
// backend can recognise. Protocol statuses (a rejected tag or signature) are
// real crypto results and must never trigger the fallback.
func wrapUnavailable(err error) error {
	if errors.Is(err, hctclient.ErrUnavailable) {
		return fmt.Errorf("%w: %v", ErrBackendUnavailable, err)
	}
	return err
}

func (b *hctBackend) call(op uint16, payload []byte) ([]byte, error) {
	resp, err := b.client.Call(context.Background(), op, payload)
	if err != nil {
		return nil, wrapUnavailable(err)
	}
	return resp, nil
}

func (b *hctBackend) streamID() uint64 {
	return b.nextStream.Add(1)
}

// ─── SM2 ────────────────────────────────────────────────────────────

func (b *hctBackend) GenerateSM2KeyPair() (*SM2PrivateKey, error) {
	resp, err := b.call(hctproto.OpSM2Keygen, nil)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 生成 SM2 密钥对失败: %w", err)
	}
	if len(resp) != SM2ScalarSize+hctSM2PubSize {
		return nil, fmt.Errorf("teecrypto: 生成 SM2 密钥对失败: 响应长度 %d", len(resp))
	}
	d := new(big.Int).SetBytes(resp[:SM2ScalarSize])
	if d.Sign() <= 0 || d.Cmp(sm2Curve.Params().N) >= 0 {
		return nil, errors.New("teecrypto: HCT 返回的 SM2 私钥标量无效")
	}
	x := new(big.Int).SetBytes(resp[SM2ScalarSize : SM2ScalarSize+32])
	y := new(big.Int).SetBytes(resp[SM2ScalarSize+32:])
	if !sm2Curve.IsOnCurve(x, y) {
		return nil, errors.New("teecrypto: HCT 返回的 SM2 公钥不在曲线上")
	}
	// Q must be d*G; a mismatch means the two halves do not belong together.
	gx, gy := sm2Curve.ScalarBaseMult(sm2ScalarBytes(d))
	if gx.Cmp(x) != 0 || gy.Cmp(y) != 0 {
		return nil, errors.New("teecrypto: HCT 返回的 SM2 密钥对不一致")
	}
	priv := &SM2PrivateKey{PublicKey: SM2PublicKey{X: x, Y: y}, D: d}
	clear(resp)
	return priv, nil
}

// sm2PointPayload marshals a public key as the 64-byte x||y the helper expects.
func sm2PointPayload(pub *SM2PublicKey) []byte {
	out := make([]byte, hctSM2PubSize)
	pub.X.FillBytes(out[:32])
	pub.Y.FillBytes(out[32:])
	return out
}

func (b *hctBackend) EncryptSM2(pub *SM2PublicKey, plaintext []byte) ([]byte, error) {
	payload := make([]byte, 0, hctSM2PubSize+len(plaintext))
	payload = append(payload, sm2PointPayload(pub)...)
	payload = append(payload, plaintext...)

	resp, err := b.call(hctproto.OpSM2Encrypt, payload)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: SM2 加密失败: %w", err)
	}
	if len(resp) != len(plaintext)+96 {
		return nil, fmt.Errorf("teecrypto: SM2 加密失败: 密文长度 %d", len(resp))
	}
	// gmsm's wire format carries the uncompressed-point prefix; libhct omits it.
	out := make([]byte, 1+len(resp))
	out[0] = 4
	copy(out[1:], resp)
	return out, nil
}

func (b *hctBackend) DecryptSM2(priv *SM2PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || ciphertext[0] != 4 {
		return nil, errors.New("teecrypto: SM2 密文缺少未压缩点前缀")
	}
	payload := make([]byte, 0, SM2ScalarSize+len(ciphertext)-1)
	payload = append(payload, sm2ScalarBytes(priv.D)...)
	payload = append(payload, ciphertext[1:]...)

	resp, err := b.call(hctproto.OpSM2Decrypt, payload)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: SM2 解密失败: %w", err)
	}
	return resp, nil
}

func (b *hctBackend) SignSM2(priv *SM2PrivateKey, userID, msg []byte) (*big.Int, *big.Int, error) {
	digest, err := sm2Digest(&priv.PublicKey, userID, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("teecrypto: SM2 签名失败: %w", err)
	}
	payload := make([]byte, 0, SM2ScalarSize+sm3Size)
	payload = append(payload, sm2ScalarBytes(priv.D)...)
	payload = append(payload, digest[:]...)

	resp, err := b.call(hctproto.OpSM2SignDigest, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("teecrypto: SM2 签名失败: %w", err)
	}
	if len(resp) != hctSM2SigSize {
		return nil, nil, fmt.Errorf("teecrypto: SM2 签名失败: 签名长度 %d", len(resp))
	}
	r := new(big.Int).SetBytes(resp[:32])
	s := new(big.Int).SetBytes(resp[32:])
	return r, s, nil
}

func (b *hctBackend) VerifySM2(pub *SM2PublicKey, userID, msg []byte, r, s *big.Int) bool {
	digest, err := sm2Digest(pub, userID, msg)
	if err != nil {
		return false
	}
	payload := make([]byte, 0, hctSM2PubSize+sm3Size+hctSM2SigSize)
	payload = append(payload, sm2PointPayload(pub)...)
	payload = append(payload, digest[:]...)
	payload = append(payload, leftPad32(r.Bytes())...)
	payload = append(payload, leftPad32(s.Bytes())...)

	_, err = b.call(hctproto.OpSM2VerifyDigest, payload)
	if err != nil {
		if se := (*hctclient.StatusError)(nil); errors.As(err, &se) &&
			se.Status == hctproto.StatusInvalidSignature {
			return false
		}
		return false
	}
	return true
}

// ─── SM3 / HMAC-SM3 ─────────────────────────────────────────────────

func (b *hctBackend) SM3Sum(data []byte) ([sm3Size]byte, error) {
	var out [sm3Size]byte
	resp, err := b.call(hctproto.OpSM3Sum, data)
	if err != nil {
		return out, err
	}
	if len(resp) != sm3Size {
		return out, fmt.Errorf("SM3 摘要长度 %d", len(resp))
	}
	copy(out[:], resp)
	return out, nil
}

func (b *hctBackend) HMACSM3(key, data []byte) ([sm3Size]byte, error) {
	var out [sm3Size]byte
	st, err := b.NewHMACSM3Stream(key)
	if err != nil {
		return out, err
	}
	if _, err := st.Write(data); err != nil {
		_ = st.Close()
		return out, err
	}
	sum, err := st.Sum()
	if err != nil {
		return out, err
	}
	return sum, nil
}

func (b *hctBackend) NewSM3Stream() (SM3Stream, error) {
	return b.newHashStream(hctproto.OpSM3Init)
}

func (b *hctBackend) newHashStream(initOp uint16) (SM3Stream, error) {
	id := b.streamID()
	payload := hctproto.NewBuilder(8)
	payload.U64(id)
	if _, err := b.call(initOp, payload.Payload()); err != nil {
		return nil, fmt.Errorf("初始化 SM3 流失败: %w", err)
	}
	return &hctSM3Stream{backend: b, id: id}, nil
}

// NewHMACSM3Stream exists for HMACSM3 and for callers that need a streaming
// HMAC; it is not part of the Backend interface.
func (b *hctBackend) NewHMACSM3Stream(key []byte) (*hctSM3Stream, error) {
	id := b.streamID()
	payload := hctproto.NewBuilder(8 + len(key))
	payload.U64(id)
	payload.Bytes(key)
	if _, err := b.call(hctproto.OpHMACSM3Init, payload.Payload()); err != nil {
		return nil, fmt.Errorf("初始化 HMAC-SM3 流失败: %w", err)
	}
	return &hctSM3Stream{backend: b, id: id, hmac: true}, nil
}

type hctSM3Stream struct {
	backend   *hctBackend
	id        uint64
	hmac      bool
	buf       []byte
	finalized bool
	closed    bool
	mu        sync.Mutex
}

func (s *hctSM3Stream) updateOp() uint16 {
	if s.hmac {
		return hctproto.OpHMACSM3Update
	}
	return hctproto.OpSM3Update
}

func (s *hctSM3Stream) finalOp() uint16 {
	if s.hmac {
		return hctproto.OpHMACSM3Final
	}
	return hctproto.OpSM3Final
}

func (s *hctSM3Stream) abortOp() uint16 {
	if s.hmac {
		return hctproto.OpHMACSM3Abort
	}
	return hctproto.OpSM3Abort
}

func (s *hctSM3Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finalized || s.closed {
		return 0, errors.New("SM3 流已结束")
	}
	s.buf = append(s.buf, p...)
	if len(s.buf) >= hctChunkSize {
		if err := s.flushLocked(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (s *hctSM3Stream) flushLocked() error {
	if len(s.buf) == 0 {
		return nil
	}
	data := s.buf
	s.buf = nil
	payload := hctproto.NewBuilder(8 + len(data))
	payload.U64(s.id)
	payload.Bytes(data)
	if _, err := s.backend.call(s.updateOp(), payload.Payload()); err != nil {
		return fmt.Errorf("SM3 更新失败: %w", err)
	}
	return nil
}

func (s *hctSM3Stream) Sum() ([sm3Size]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [sm3Size]byte
	if s.finalized || s.closed {
		return out, errors.New("SM3 流已结束")
	}
	if err := s.flushLocked(); err != nil {
		return out, err
	}
	payload := hctproto.NewBuilder(8)
	payload.U64(s.id)
	resp, err := s.backend.call(s.finalOp(), payload.Payload())
	if err != nil {
		return out, fmt.Errorf("SM3 摘要失败: %w", err)
	}
	if len(resp) != sm3Size {
		return out, fmt.Errorf("SM3 摘要长度 %d", len(resp))
	}
	copy(out[:], resp)
	s.finalized = true
	return out, nil
}

func (s *hctSM3Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.finalized {
		return nil
	}
	payload := hctproto.NewBuilder(8)
	payload.U64(s.id)
	_, err := s.backend.call(s.abortOp(), payload.Payload())
	return err
}

// ─── SM4-GCM ────────────────────────────────────────────────────────

func (b *hctBackend) NewGCM(key []byte) (GCM, error) {
	if len(key) != SM4KeySize {
		return nil, ErrInvalidKeySize
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &hctGCM{backend: b, key: k}, nil
}

type hctGCM struct {
	backend *hctBackend
	key     []byte
}

func (g *hctGCM) NonceSize() int { return 12 }
func (g *hctGCM) Overhead() int  { return 16 }

func (g *hctGCM) initStream(nonce []byte, enc bool) (uint64, error) {
	if len(nonce) != g.NonceSize() {
		return 0, fmt.Errorf("GCM nonce 长度无效: %d", len(nonce))
	}
	id := g.backend.streamID()
	payload := hctproto.NewBuilder(8 + 1 + 4 + len(g.key) + len(nonce))
	payload.U64(id)
	if enc {
		payload.U8(1)
	} else {
		payload.U8(0)
	}
	payload.U32(uint32(len(g.key)))
	payload.Bytes(g.key)
	payload.Bytes(nonce)
	if _, err := g.backend.call(hctproto.OpGCMInit, payload.Payload()); err != nil {
		return 0, fmt.Errorf("GCM 初始化失败: %w", err)
	}
	return id, nil
}

func (g *hctGCM) abort(id uint64) {
	payload := hctproto.NewBuilder(8)
	payload.U64(id)
	_, _ = g.backend.call(hctproto.OpGCMAbort, payload.Payload())
}

func (g *hctGCM) aad(id uint64, aad []byte) error {
	if len(aad) == 0 {
		return nil
	}
	payload := hctproto.NewBuilder(8 + len(aad))
	payload.U64(id)
	payload.Bytes(aad)
	if _, err := g.backend.call(hctproto.OpGCMAAD, payload.Payload()); err != nil {
		return fmt.Errorf("GCM AAD 失败: %w", err)
	}
	return nil
}

// update encrypts or decrypts plaintext in chunks. The plaintext is returned
// unauthenticated for decryption; Open only hands it back after FINAL.
func (g *hctGCM) update(id uint64, in []byte) ([]byte, error) {
	out := make([]byte, 0, len(in))
	for off := 0; off < len(in); off += hctChunkSize {
		end := off + hctChunkSize
		if end > len(in) {
			end = len(in)
		}
		payload := hctproto.NewBuilder(8 + end - off)
		payload.U64(id)
		payload.Bytes(in[off:end])
		resp, err := g.backend.call(hctproto.OpGCMUpdate, payload.Payload())
		if err != nil {
			return nil, fmt.Errorf("GCM 更新失败: %w", err)
		}
		if len(resp) != end-off {
			return nil, fmt.Errorf("GCM 输出长度 %d, 期望 %d", len(resp), end-off)
		}
		out = append(out, resp...)
	}
	return out, nil
}

func (g *hctGCM) sealFinal(id uint64) ([]byte, error) {
	payload := hctproto.NewBuilder(8)
	payload.U64(id)
	resp, err := g.backend.call(hctproto.OpGCMFinal, payload.Payload())
	if err != nil {
		return nil, fmt.Errorf("GCM 认证失败: %w", err)
	}
	if len(resp) != g.Overhead() {
		return nil, fmt.Errorf("GCM 标签长度 %d", len(resp))
	}
	return resp, nil
}

func (g *hctGCM) SetTag(id uint64, tag []byte) error {
	if len(tag) != g.Overhead() {
		return fmt.Errorf("GCM 标签长度无效: %d", len(tag))
	}
	payload := hctproto.NewBuilder(8 + len(tag))
	payload.U64(id)
	payload.Bytes(tag)
	if _, err := g.backend.call(hctproto.OpGCMSetTag, payload.Payload()); err != nil {
		return fmt.Errorf("GCM 设置标签失败: %w", err)
	}
	return nil
}

func (g *hctGCM) Seal(dst, nonce, plaintext, aad []byte) ([]byte, error) {
	id, err := g.initStream(nonce, true)
	if err != nil {
		return nil, err
	}
	// AAD must be absorbed before ciphertext, the same order the SW backend
	// computes GHASH in.
	if err := g.aad(id, aad); err != nil {
		g.abort(id)
		return nil, err
	}
	ct, err := g.update(id, plaintext)
	if err != nil {
		g.abort(id)
		return nil, err
	}
	tag, err := g.sealFinal(id)
	if err != nil {
		return nil, err
	}
	// AEAD layout: nonce stays wherever the caller placed it; append ct||tag.
	out := append(dst, ct...)
	out = append(out, tag...)
	return out, nil
}

func (g *hctGCM) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < g.Overhead() {
		return nil, ErrCiphertextTooShort
	}
	sealed, tag := ciphertext[:len(ciphertext)-g.Overhead()], ciphertext[len(ciphertext)-g.Overhead():]

	id, err := g.initStream(nonce, false)
	if err != nil {
		return nil, err
	}
	if err := g.SetTag(id, tag); err != nil {
		g.abort(id)
		return nil, err
	}
	if err := g.aad(id, aad); err != nil {
		g.abort(id)
		return nil, err
	}
	plaintext, err := g.update(id, sealed)
	if err != nil {
		g.abort(id)
		return nil, err
	}
	payload := hctproto.NewBuilder(8)
	payload.U64(id)
	if _, err := g.backend.call(hctproto.OpGCMFinal, payload.Payload()); err != nil {
		// Never hand back unauthenticated plaintext.
		clear(plaintext)
		return nil, fmt.Errorf("GCM 认证失败: %w", err)
	}
	return append(dst, plaintext...), nil
}
