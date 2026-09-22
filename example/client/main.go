package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/http3/qlog"
)

func main() {
	insecure := flag.Bool("insecure", true, "skip certificate verification")
	flag.Parse()
	urls := []string{""}

	var c *quic.Conn
	roundTripper := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         "your-domain",
			InsecureSkipVerify: *insecure,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
				fmt.Println(cert.Subject.CommonName)
				return nil
			},
		},
		QUICConfig: &quic.Config{
			// InitialStreamReceiveWindow:     1024 * 1024 * 20,
			// MaxStreamReceiveWindow:         1024 * 1024 * 40,
			// InitialConnectionReceiveWindow: 1024 * 1024 * 20,
			// MaxConnectionReceiveWindow:     1024 * 1024 * 40,
			Tracer: qlog.DefaultConnectionTracer,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			fmt.Println(tlsCfg.ServerName)
			conn, err := quic.DialAddr(ctx, "your-ip", tlsCfg, cfg)
			c = conn
			return c, err
		},
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		// Transport: &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 	return tls.Dial(network, "your-ip", &tls.Config{
		// 		ServerName: "your-ip", InsecureSkipVerify: *insecure, VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// 			cert, err := x509.ParseCertificate(rawCerts[0])
		// 			if err != nil {
		// 				return err
		// 			}
		// 			fmt.Println(cert.Subject.CommonName)
		// 			return nil
		// 		}})
		// },
		// 	ReadBufferSize:    40 * 1024 * 1024,
		// 	WriteBufferSize:   40 * 1024 * 1024,
		// 	ForceAttemptHTTP2: true},
		// --- 取消上方注释，并注释下方为测试tcp，反之为默认quic
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	for _, addr := range urls {
		wg.Add(1)
		log.Printf("GET %s", addr)
		go func(addr string) {
			start := time.Now()
			rsp, err := hclient.Get("https://your-domain/test.bin")
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			body.Grow(512 * 1024 * 1024)
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("%f Mbps\n", float64(body.Len())/1024.0/1024.0/float64(time.Since(start).Seconds())*8)
			if c != nil {
				log.Printf("client数据 最小rtt%v\t平均rtt差%v\t平滑rtt%v",
					c.ConnectionStats().MinRTT, c.ConnectionStats().MeanDeviation, c.ConnectionStats().SmoothedRTT)
				log.Panicln("server数据见服务器stderr")
			}
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
