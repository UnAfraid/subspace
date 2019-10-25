package main

//go:generate go-bindata -ignore=\.go templates/... email/... static/...

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/mattn/go-colorable"
	"gopkg.in/natefinch/lumberjack.v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/securecookie"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

const TimestampFormat = "2006-01-02 15:04:05"

var (
	// Flags
	cli = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// datadir
	datadir string

	// The version is set by the build command.
	version string

	// httpd
	httpAddr   string
	httpHost   string
	httpPrefix string

	// Insecure http cookies (only recommended for internal LANs/VPNs)
	httpInsecure bool

	// set based on httpAddr
	httpIP   string
	httpPort string

	// backlink
	backlink string

	// show version
	showVersion bool

	// show help
	showHelp bool

	// debug logging
	debug bool

	// Let's Encrypt
	letsencrypt bool

	// HTTP read limit
	httpReadLimit int64 = 2 * (1024 * 1024)

	// securetoken
	securetoken *securecookie.SecureCookie

	// config
	config *Config

	// mailer
	mailer = NewMailer()

	// SAML
	samlSP *samlsp.Middleware

	// Error page HTML
	errorPageHTML = `<html><head><title>Error</title></head><body text="orangered" bgcolor="black"><h1>An error has occurred</h1></body></html>`

	wireguardPort int
	// Client ipv4 configuration
	clientIPv4Subnet     string
	clientIPv4Gateway    string
	clientIPv4UseGateway bool
	clientIPv4DNS        string
	clientIPv4UseDNS     bool

	// Client ipv6 configuration
	clientIPv6Enabled    bool
	clientIPv6Subnet     string
	clientIPv6Gateway    string
	clientIPv6UseGateway bool
	clientIPv6DNS        string
	clientIPv6UseDNS     bool

	clientKeepAlive int
)

func init() {
	cli.StringVar(&datadir, "datadir", "/data", "data dir")
	cli.StringVar(&backlink, "backlink", "", "backlink (optional)")
	cli.StringVar(&httpHost, "http-host", "", "HTTP host")
	cli.StringVar(&httpAddr, "http-addr", ":80", "HTTP listen address")
	cli.BoolVar(&httpInsecure, "http-insecure", false, "enable sessions cookies for http (no https) not recommended")
	cli.BoolVar(&letsencrypt, "letsencrypt", true, "enable TLS using Let's Encrypt on port 443")

	cli.IntVar(&wireguardPort, "wireguard-port", 51820, "the wireguard port")
	cli.StringVar(&clientIPv4Subnet, "client-ipv4-subnet", "10.99.97.0/24", "the wireguard client ipv4 subnet example 10.99.97.0/24")
	cli.StringVar(&clientIPv4Gateway, "client-ipv4-gateway", "10.99.97.1", "the wireguard client ipv4 gateway")
	cli.BoolVar(&clientIPv4UseGateway, "client-ipv4-use-gateway", true, "enables the wireguard client ipv4 gateway")
	cli.StringVar(&clientIPv4DNS, "client-ipv4-dns", "10.99.97.1", "the wireguard client ipv4 dns")
	cli.BoolVar(&clientIPv4UseDNS, "client-ipv4-use-dns", true, "enables the wireguard client ipv4 dns")

	cli.BoolVar(&clientIPv6Enabled, "client-ipv6-enabled", false, "enables/disables ipv6 client support")
	cli.StringVar(&clientIPv6Subnet, "client-ipv6-subnet", "fd00::10:97:0/112", "the wireguard client ipv6 subnet example 10.99.97.0/24")
	cli.StringVar(&clientIPv6Gateway, "client-ipv6-gateway", "fd00::10:97:1", "the wireguard client ipv6 gateway")
	cli.BoolVar(&clientIPv6UseGateway, "client-ipv6-use-gateway", true, "enables the wireguard client ipv6 gateway")
	cli.StringVar(&clientIPv6DNS, "client-ipv6-dns", "fd00::10:97:1", "the wireguard client ipv6 dns")
	cli.BoolVar(&clientIPv6UseDNS, "client-ipv6-use-dns", true, "enables the wireguard client ipv6 dns")

	cli.IntVar(&clientKeepAlive, "client-keep-alive", 0, "enables keep alive")

	cli.BoolVar(&showVersion, "version", false, "display version and exit")
	cli.BoolVar(&showHelp, "help", false, "display help and exit")
	cli.BoolVar(&debug, "debug", false, "debug mode")
}

func main() {
	var err error

	err = cli.Parse(os.Args[1:])
	if err != nil {
		logrus.Fatal(err)
		return
	}

	usage := func(msg string) {
		if msg != "" {
			logrus.Errorf("ERROR: %s", msg)
		}
		logrus.Errorf("Usage: %s --http-host subspace.example.com\n", os.Args[0])
		cli.PrintDefaults()
	}

	if showHelp {
		usage("Help info")
		os.Exit(0)
		return
	}

	if showVersion {
		fmt.Printf("Subspace %s\n", version)
		os.Exit(0)
		return
	}

	// http host
	if httpHost == "" {
		usage("--http-host flag is required")
		os.Exit(1)
		return
	}

	initLogger()
	logrus.Debugf("debug logging is enabled")

	// http port
	httpIP, httpPort, err := net.SplitHostPort(httpAddr)
	if err != nil {
		usage("invalid --http-addr: " + err.Error())
		return
	}

	if clientKeepAlive > 0 && clientKeepAlive < 10 {
		usage("invalid --client-keep-alive value, cannot be less then 10 seconds")
		return
	}

	// Clean datadir path.
	datadir = filepath.Clean(datadir)

	// config
	config, err = NewConfig("config.json")
	if err != nil {
		logrus.Fatal(err)
		return
	}

	// Secure token
	securetoken = securecookie.New([]byte(config.FindInfo().HashKey), []byte(config.FindInfo().BlockKey))

	// Configure SAML if metadata is present.
	if len(config.FindInfo().SAML.IDPMetadata) > 0 {
		if err := configureSAML(); err != nil {
			logrus.Warnf("configuring SAML failed: %s", err)
		}
	}

	//
	// Routes
	//
	r := &httprouter.Router{}
	r.GET("/", Log(WebHandler(indexHandler, "index")))
	r.GET("/help", Log(WebHandler(helpHandler, "help")))
	r.GET("/configure", Log(WebHandler(configureHandler, "configure")))
	r.POST("/configure", Log(WebHandler(configureHandler, "configure")))

	// SAML
	r.GET("/sso", Log(ssoHandler))
	r.GET("/saml/metadata", Log(samlHandler))
	r.POST("/saml/metadata", Log(samlHandler))
	r.GET("/saml/acs", Log(samlHandler))
	r.POST("/saml/acs", Log(samlHandler))

	r.GET("/signin", Log(WebHandler(signinHandler, "signin")))
	r.GET("/signout", Log(WebHandler(signoutHandler, "signout")))
	r.POST("/signin", Log(WebHandler(signinHandler, "signin")))
	r.GET("/forgot", Log(WebHandler(forgotHandler, "forgot")))
	r.POST("/forgot", Log(WebHandler(forgotHandler, "forgot")))

	r.GET("/settings", Log(WebHandler(settingsHandler, "settings")))
	r.POST("/settings", Log(WebHandler(settingsHandler, "settings")))

	r.GET("/user/edit/:user", Log(WebHandler(userEditHandler, "user/edit")))
	r.POST("/user/edit", Log(WebHandler(userEditHandler, "user/edit")))
	r.GET("/user/delete/:user", Log(WebHandler(userDeleteHandler, "user/delete")))
	r.POST("/user/delete", Log(WebHandler(userDeleteHandler, "user/delete")))

	r.GET("/profile/add", Log(WebHandler(profileAddHandler, "profile/add")))
	r.POST("/profile/add", Log(WebHandler(profileAddHandler, "profile/add")))
	r.GET("/profile/connect/:profile", Log(WebHandler(profileConnectHandler, "profile/connect")))
	r.GET("/profile/delete/:profile", Log(WebHandler(profileDeleteHandler, "profile/delete")))
	r.POST("/profile/delete", Log(WebHandler(profileDeleteHandler, "profile/delete")))
	r.GET("/profile/config/wireguard/:profile", Log(WebHandler(wireguardConfigHandler, "profile/config/wireguard")))
	r.GET("/profile/qrconfig/wireguard/:profile", Log(WebHandler(wireguardQRConfigHandler, "profile/qrconfig/wireguard")))
	r.GET("/static/*path", staticHandler)

	//
	// Server
	//

	httpTimeout := 10 * time.Minute
	maxHeaderBytes := 10 * (1024 * 1024)

	// Plain text web server for use behind a reverse proxy.
	if !letsencrypt {
		httpServer := &http.Server{
			Handler:        r,
			Addr:           net.JoinHostPort(httpIP, httpPort),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		hostPort := net.JoinHostPort(httpHost, httpPort)
		if httpPort == "80" {
			hostPort = httpHost
		}
		logrus.Infof("Subspace version: %s %s", version, &url.URL{
			Scheme: "http",
			Host:   hostPort,
			Path:   httpPrefix,
		})
		logrus.Fatal(httpServer.ListenAndServe())
	}

	// Let's Encrypt TLS mode

	// autocert
	certmanager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(datadir, "letsencrypt")),
		HostPolicy: func(_ context.Context, host string) error {
			host = strings.TrimPrefix(host, "www.")
			if host == httpHost {
				return nil
			}
			if host == config.FindInfo().Domain {
				return nil
			}
			return fmt.Errorf("autocert: host %q not permitted by HostPolicy", host)
		},
	}

	// http redirect to https and Let's Encrypt auth
	go func() {
		redir := httprouter.New()
		redir.GET("/*path", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			r.URL.Scheme = "https"
			r.URL.Host = httpHost
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		})

		httpServer := &http.Server{
			Handler:        certmanager.HTTPHandler(redir),
			Addr:           net.JoinHostPort(httpIP, "80"),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		if err := httpServer.ListenAndServe(); err != nil {
			logrus.Fatalf("http server on port 80 failed: %s", err)
		}
	}()

	// TLS
	tlsConfig := tls.Config{
		GetCertificate:           certmanager.GetCertificate,
		NextProtos:               []string{"http/1.1"},
		Rand:                     rand.Reader,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Override default for TLS.
	if httpPort == "80" {
		httpPort = "443"
		httpAddr = net.JoinHostPort(httpIP, httpPort)
	}

	httpServer := &http.Server{
		Handler:        r,
		Addr:           httpAddr,
		WriteTimeout:   httpTimeout,
		ReadTimeout:    httpTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}

	// Enable TCP keep alives on the TLS connection.
	tcpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		logrus.Fatalf("listen failed: %s", err)
		return
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{tcpListener.(*net.TCPListener)}, &tlsConfig)

	hostPort := net.JoinHostPort(httpHost, httpPort)
	if httpPort == "443" {
		hostPort = httpHost
	}
	logrus.Infof("Subspace version: %s %s", version, &url.URL{
		Scheme: "https",
		Host:   hostPort,
		Path:   "/",
	})
	logrus.Fatal(httpServer.Serve(tlsListener))
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := l.AcceptTCP()
	if err != nil {
		return
	}

	if err := tc.SetKeepAlive(true); err != nil {
		return nil, err
	}

	if err := tc.SetKeepAlivePeriod(10 * time.Minute); err != nil {
		return nil, err
	}
	return tc, nil
}

func configureSAML() error {
	info := config.FindInfo()

	if len(info.SAML.IDPMetadata) == 0 {
		return fmt.Errorf("no IDP metadata")
	}
	entity := &saml.EntityDescriptor{}
	err := xml.Unmarshal([]byte(info.SAML.IDPMetadata), entity)

	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal([]byte(info.SAML.IDPMetadata), entities); err != nil {
			return err
		}

		err = fmt.Errorf("no entity found with IDPSSODescriptor")
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				entity = &entities.EntityDescriptors[i]
				err = nil
			}
		}
	}
	if err != nil {
		return err
	}

	keyPair, err := tls.X509KeyPair(info.SAML.Certificate, info.SAML.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load SAML keypair: %s", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse SAML certificate: %s", err)
	}

	rootURL := url.URL{
		Scheme: "https",
		Host:   httpHost,
		Path:   "/",
	}

	newsp, err := samlsp.New(samlsp.Options{
		URL:               rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       entity,
		CookieName:        SessionCookieNameSSO,
		CookieDomain:      httpHost, // TODO: this will break if using a custom domain.
		CookieSecure:      !httpInsecure,
		Logger:            logrus.StandardLogger(),
		AllowIDPInitiated: true,
	})
	if err != nil {
		logrus.Warnf("failed to configure SAML: %s", err)
		samlSP = nil
		return fmt.Errorf("failed to configure SAML: %s", err)
	}
	samlSP = newsp
	logrus.Infof("successfully configured SAML")
	return nil
}

func BestDomain() string {
	domain := config.FindInfo().Domain
	if domain != "" {
		return domain
	}
	return httpHost
}

func initLogger() {
	var logLevel = logrus.InfoLevel
	if debug {
		logLevel = logrus.DebugLevel
	}

	logrus.SetLevel(logLevel)
	logrus.SetOutput(colorable.NewColorableStdout())
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: TimestampFormat,
	})

	// Lumberjack hook
	logrus.AddHook(NewLumberjackHook(
		&LumberjackHookConfig{
			Level: logLevel,
			Formatter: &logrus.TextFormatter{
				FullTimestamp:   true,
				TimestampFormat: TimestampFormat,
			},
		},
		&lumberjack.Logger{
			Filename:   "/tmp/console.log",
			MaxSize:    50, // megabytes
			MaxBackups: 3,
			MaxAge:     28, //days
			Compress:   true,
			LocalTime:  true,
		},
	))
}
