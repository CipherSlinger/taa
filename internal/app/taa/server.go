package taa

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"taa/internal/controller"
)

// newTAAServer 注册 TAA 控制器路由并创建配置了安全超时的 HTTP Server 实例
func newTAAServer(addr string, state *controller.TAAState) *http.Server {
	mux := http.NewServeMux()
	controller.RegisterRoutes(mux, state)

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// startServer 启动 TAA HTTP 服务，并在 ctx 被取消时触发优雅停机。
// 若服务启动或运行期间发生非 http.ErrServerClosed 的错误，则通过 errChan 上报。
func startServer(ctx context.Context, addr string, state *controller.TAAState) error {
	server := newTAAServer(addr, state)
	errChan := make(chan error, 1)

	go func() {
		log.Printf("taa service listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Printf("taa service received shutdown signal, shutting down gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errChan:
		return err
	}
}
