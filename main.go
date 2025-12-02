package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type ProxyConfig struct {
	Host      string
	TargetURL url.URL
}

func main() {
	dir := filepath.Join(os.Getenv("HOME"), ".muxi")

	list := flag.Bool("list", false, "Pass this to list all configured hosts")
	host := flag.String("host", "", "Pass this when you want to update hostname configuration")
	port := flag.Int64("port", 0, "Pass this to define the local port that the proxy will forward requests to from the hostname above")
	remove := flag.Bool("remove", false, "Pass this to remove the host configuration for the hostname above")
	daemon := flag.Bool("daemon", false, "Run the muxi proxy server daemon")
	flag.Parse()

	// List mode - lists all configured hosts and exits
	if *list {
		config, err := LoadConfig(dir)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		for _, hostConfig := range config.Hosts {
			fmt.Printf("Host: %s -> Port: %s\n", hostConfig.Host, hostConfig.TargetPort)
		}
		return
	}

	// Config mode - updates the config file exits
	if *host != "" && *port != 0 {
		err := AddHost(dir, *host, fmt.Sprintf("%d", *port))
		if err != nil {
			log.Fatalf("Failed to add host: %v", err)
		}
		log.Printf("Added host %s forwarding to port %d", *host, *port)
		return
	} else if host != nil && *remove {
		err := RemoveHost(dir, *host)
		if err != nil {
			log.Fatalf("Failed to remove host: %v", err)
		}
		log.Printf("Removed host %s from configuration", *host)
		return
	} else if *host != "" {
		log.Fatalf("To add a host, please provide both --host and --port. To remove a host, provide --host and --remove.")
	}

	// If --daemon is passed, start the proxy server

	if !(*daemon) {
		log.Fatalf("No operation specified. Use --help for usage information.")
		return
	}

	certManager, err := NewCertificateManager(dir)
	if err != nil {
		log.Fatalf("Failed to create certificate manager: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get config
		config, err := LoadConfig(dir)
		if err != nil {
			log.Printf("Failed to reload config: %v", err)
			http.Error(w, "Config error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Find the matching host configuration
		var targetPort string
		for _, hostConfig := range config.Hosts {
			if hostConfig.Host == r.Host {
				targetPort = hostConfig.TargetPort
				break
			}
		}

		if targetPort == "" {
			log.Printf("Unknown host: %s (not in config)", r.Host)
			http.Error(w, "Unknown host", http.StatusNotFound)
			return
		}

		// Create proxy on-demand for this request
		targetURL := url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", targetPort)}
		proxy := httputil.NewSingleHostReverseProxy(&targetURL)

		// Use a transport with timeouts so upstream connection failures return quickly
		proxy.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		// Return 502 Bad Gateway when upstream doesn't answer or other network errors occur.
		proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Printf("Upstream error for host %s -> %v", targetURL.String(), err)
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.WriteHeader(http.StatusBadGateway)
			io.WriteString(rw, "<html><body><center><h1>502 Bad Gateway</h1><p>Upstream host did not respond</p><p>muxi the muxer proxy</p></center></body></html>")
		}

		proxy.ServeHTTP(w, r)
	})

	tlsConfig := &tls.Config{GetCertificate: certManager.GetCertificate}
	srv := &http.Server{Addr: ":443", Handler: handler, TLSConfig: tlsConfig}

	// Start a background updater that refreshes /etc/hosts every 5 seconds while the web server is running.
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := UpdateEtcHosts(); err != nil {
					log.Printf("UpdateEtcHosts error: %v", err)
				}
			case <-done:
				return
			}
		}
	}()

	err = srv.ListenAndServeTLS("", "")
	close(done)
	if err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}
