package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	// 配置服务器参数
	addr := ":443"
	Dir := "./testdata"

	// 读取证书
	cert, err := tls.LoadX509KeyPair("cert.file", "key.file")
	if err != nil {
		log.Fatalf("生成自签名证书失败: %v", err)
	}

	// 配置 TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // HTTP/3 要求 TLS 1.3
	}

	// 创建文件服务器
	fileServer := http.FileServer(http.Dir(Dir))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 提供文件服务
		fileServer.ServeHTTP(w, r)
	})

	// 创建 HTTP/3 服务器（基于 quic-go）
	server := &http3.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		// false表示使用bdp限制因子为3
		QUICConfig: &quic.Config{Congestion: func() quic.SendAlgorithmWithDebugInfos { return quic.NewMCC(nil, false) }},
		Handler:    handler,
	}

	// 启动服务器（阻塞运行）
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
