package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/szampardi/hermes"
	log "github.com/szampardi/msg"

	"github.com/szampardi/xprint/temple"
	"gopkg.in/yaml.v3"
)

type (
	configuration struct {
		Outfile          string        `json:"Outfile,omitempty" yaml:"Outfile,omitempty"`
		ConcurrentChecks int           `json:"ConcurrenctChecks,omitempty" yaml:"ConcurrenctChecks,omitempty"`
		Timeout          time.Duration `json:"Timeout,omitempty" yaml:"Timeout,omitempty"`
		LoopDelay        time.Duration `json:"LoopDelay,omitempty" yaml:"LoopDelay,omitempty"`
		RetryDelay       time.Duration `json:"RetryDelay,omitempty" yaml:"RetryDelay,omitempty"`
		RetryAttempts    int           `json:"RetryAttempts,omitempty" yaml:"RetryAttempts,omitempty"`
		Alerts           string        `json:"Alerts,omitempty" yaml:"Alerts,omitempty"`
		PageTitle        string        `json:"PageTitle,omitempty" yaml:"PageTitle,omitempty"`
		ListenAddr       string        `json:"ListenAddr,omitempty" yaml:"ListenAddr,omitempty"`
		TLSCertFile      string        `json:"TLSCertFile,omitempty" yaml:"TLSCertFile,omitempty"`
		TLSKeyFile       string        `json:"TLSKeyFile,omitempty" yaml:"TLSKeyFile,omitempty"`
		Targets          []*Target     `json:"Targets,omitempty" yaml:"Targets,omitempty"`
	}
	Target struct {
		ID                 string        `json:"ID,omitempty" yaml:"ID,omitempty"`
		Category           string        `json:"Category,omitempty" yaml:"Category,omitempty"`
		Method             string        `json:"Method,omitempty" yaml:"Method,omitempty"`
		URL                string        `json:"URL,omitempty" yaml:"URL,omitempty"`
		Headers            []string      `json:"Headers,omitempty" yaml:"Headers,omitempty"`
		ExpectedStatusCode int           `json:"StatusCode,omitempty" yaml:"StatusCode,omitempty"`
		Timeout            time.Duration `json:"Timeout,omitempty" yaml:"Timeout,omitempty"`
		RetryAttempts      int           `json:"RetryAttempts,omitempty" yaml:"RetryAttempts,omitempty"`
		DNSAddress         string        `json:"DNSAddress,omitempty" yaml:"DNSAddress,omitempty"`
		TLSSkipVerify      bool          `json:"TLSSkipVerify,omitempty" yaml:"TLSSkipVerify,omitempty"`
		clt                *http.Client
	}
)

var (
	defaultWebHook        string
	l                     log.Logger
	logfmt                log.Format = log.Formats[log.PlainFormat]
	loglvl                log.Lvl    = log.LNotice
	logcolor                         = flag.Bool("C", false, "colorize output")
	conf                             = &configuration{}
	dumpconf              bool
	format                = flag.String("f", "json", "output format (html|json|yaml)")
	htmlTemplate          = flag.String("H", "index.html", "HTML template")
	templates             = map[string]string{}
	confFile              string
	showVersion           *bool = flag.Bool("V", false, "print build version/date and exit")
	semver, commit, built       = "v0.0.0-dev", "local", "a while ago"
)

func init() {
	temple.FnMap.Fn("check", "", check, false)
	flag.Func(
		"F",
		fmt.Sprintf("logging format (prefix) %v", logFmts()),
		func(value string) error {
			if v, ok := log.Formats[value]; ok {
				logfmt = v
				return nil
			}
			return fmt.Errorf("invalid format [%s] specified", value)
		},
	)
	flag.Func(
		"L",
		"log level",
		func(value string) error {
			i, err := strconv.Atoi(value)
			if err != nil {
				return err
			}
			loglvl = log.Lvl(i)
			return log.IsValidLevel(i)
		},
	)
	flag.StringVar(&conf.Outfile, "o", os.Stdout.Name(), "output file")
	flag.IntVar(&conf.ConcurrentChecks, "concurrency", 4, "concurrent checks")
	flag.DurationVar(&conf.Timeout, "timeout", 10*time.Second, "checks' timeout")
	flag.DurationVar(&conf.RetryDelay, "delay", 5*time.Second, "delay between failed attempts and retries")
	flag.DurationVar(&conf.LoopDelay, "loop", 0, "loop and rerun every time.Duration >0")
	flag.IntVar(&conf.RetryAttempts, "retry", 1, "generic retry counter for failed checks")
	flag.StringVar(&conf.Alerts, "alerts", os.Getenv("WEBHOOK"), "URL to POST alerts to")
	flag.StringVar(&conf.PageTitle, "title", "Status Dashboard", "webpage title")
	flag.StringVar(&conf.ListenAddr, "listen", "", "listen address")
	flag.StringVar(&conf.TLSCertFile, "tls-cert", "", "TLS fullchain")
	flag.StringVar(&conf.TLSKeyFile, "tls-key", "", "TLS key")

	flag.StringVar(&confFile, "config", "", "configuration file to use")
	flag.BoolVar(&dumpconf, "dump", false, "dump loaded config (including arguments) to yaml")

	for !flag.Parsed() {
		flag.Parse()
	}
	if defaultWebHook != "" {
		hermes.WebHook = defaultWebHook
		if conf.Alerts == "" {
			conf.Alerts = defaultWebHook
		}
	}
	if conf.Alerts != "" {
		hermes.WebHook = conf.Alerts
	}

	if *showVersion {
		fmt.Fprintf(os.Stderr, "github.com/szampardi/srvmon version %s (%s) built %s\n", semver, commit, built)
		os.Exit(0)
	}

	var err error
	if err = log.IsValidLevel(int(loglvl)); err != nil {
		panic(err)
	}
	l, err = log.New(logfmt.String(), log.Formats[log.DefTimeFmt].String(), loglvl, *logcolor, "srvmon", os.Stderr)
	if err != nil {
		panic(err)
	}

	htmlTpl, err := os.ReadFile(*htmlTemplate)
	if err == nil {
		l.Debugf("using %s as HTML template", *htmlTemplate)
		templates["index"] = string(htmlTpl)
	} else {
		l.Debugf("%s", err)
		templates["index"] = defaultIndex
	}

	if confFile != "" {
		if b, err := ioutil.ReadFile(confFile); err != nil {
			l.Panic(err.Error())
		} else {
			if strings.HasSuffix(strings.ToUpper(confFile), ".JSON") {
				if err := json.Unmarshal(b, &conf); err != nil {
					l.Panic(err.Error())
				}
			} else {
				if err := yaml.Unmarshal(b, &conf); err != nil {
					l.Panic(err.Error())
				}
			}
		}
	}

	for _, arg := range flag.Args() {
		tgt := new(Target)
		for i, p := range strings.Split(arg, ",") {
			switch i {
			case 0:
				tgt.ID = p
			case 1:
				tgt.Category = p
			case 2:
				tgt.URL = p
			case 3:
				tgt.Method = strings.ToUpper(p)
			case 4:
				if sc, err := strconv.Atoi(p); err == nil {
					tgt.ExpectedStatusCode = sc
				}
			case 5:
				if rt, err := strconv.Atoi(p); err == nil {
					tgt.RetryAttempts = rt
				}
			case 6:
				tgt.DNSAddress = p
			case 7:
				v, err := strconv.ParseBool(p)
				if err == nil {
					tgt.TLSSkipVerify = v
				}
			}
		}
		conf.Targets = append(conf.Targets, tgt)
	}
}

func main() {
	if dumpconf {
		switch strings.ToUpper(*format) {
		case "JSON":
			if err := json.NewEncoder(os.Stdout).Encode(conf); err != nil {
				l.Panic(err.Error())
			}
		case "YML", "YAML":
			fallthrough
		default:
			if err := yaml.NewEncoder(os.Stdout).Encode(conf); err != nil {
				l.Panic(err.Error())
			}
		}
		os.Exit(0)
	}
	asyncOutput := struct {
		o *output
		m *sync.Mutex
	}{
		check(conf.Targets, conf.ConcurrentChecks),
		&sync.Mutex{},
	}
	go func() {
	loop:
		if conf.LoopDelay > 0 {
			time.Sleep(conf.LoopDelay)
		}
		newo := check(conf.Targets, conf.ConcurrentChecks)
		asyncOutput.m.Lock()
		asyncOutput.o = newo
		asyncOutput.m.Unlock()
		if conf.LoopDelay > 0 {
			goto loop
		}
	}()
	if conf.ListenAddr != "" {
		url, err := url.Parse(conf.ListenAddr)
		if err != nil {
			l.Panic(err.Error())
		}
		asyncHTMLOutput := struct {
			o *bytes.Buffer
			m *sync.Mutex
		}{
			new(bytes.Buffer),
			&sync.Mutex{},
		}
		go func() {
			tpl, _, err := temple.FnMap.BuildHTMLTemplate(
				false,
				conf.PageTitle,
				"",
				templates,
			)
			if err != nil {
				l.Panic(err.Error())
			}
		loop:
			time.Sleep(conf.LoopDelay + 1*time.Second)
			b := new(bytes.Buffer)
			asyncOutput.m.Lock()
			if err := tpl.ExecuteTemplate(b, "index", struct {
				Conf   *configuration
				Output *output
			}{
				conf,
				asyncOutput.o,
			}); err != nil {
				l.Panic(err.Error())
			}
			asyncOutput.m.Unlock()
			asyncHTMLOutput.m.Lock()
			asyncHTMLOutput.o = b
			asyncHTMLOutput.m.Unlock()
			goto loop
		}()
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			defer l.Noticef("%s (yaml) server finished request %s %s", url.Scheme, r.RemoteAddr, r.Method)
			if r.Method != "GET" {
				rw.WriteHeader(http.StatusMethodNotAllowed)
				http.NotFound(rw, r)
			}
			r.Header.Set("Content-Type", "text/html")
			asyncHTMLOutput.m.Lock()
			if _, err := rw.Write(asyncHTMLOutput.o.Bytes()); err != nil {
				l.Errorf("%s (/) error: %s", url.Scheme, err)
			}
			asyncHTMLOutput.m.Unlock()
		})
		mux.HandleFunc("/json", func(rw http.ResponseWriter, r *http.Request) {
			defer l.Noticef("%s (yaml) server finished request %s %s", url.Scheme, r.RemoteAddr, r.Method)
			if r.Method != "GET" {
				rw.WriteHeader(http.StatusMethodNotAllowed)
			}
			r.Header.Set("Content-Type", "application/json")
			asyncOutput.m.Lock()
			rw.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(rw).Encode(asyncOutput.o); err != nil {
				l.Errorf("%s (/json) error: %s", url.Scheme, err)
			}
			asyncOutput.m.Unlock()
		})
		mux.HandleFunc("/yaml", func(rw http.ResponseWriter, r *http.Request) {
			defer l.Noticef("%s (yaml) server finished request %s %s", url.Scheme, r.RemoteAddr, r.Method)
			if r.Method != "GET" {
				rw.WriteHeader(http.StatusMethodNotAllowed)
			}
			r.Header.Set("Content-Type", "text/plain")
			asyncOutput.m.Lock()
			if err := yaml.NewEncoder(rw).Encode(asyncOutput.o); err != nil {
				l.Errorf("%s (/yaml) error: %s", url.Scheme, err)
			}
			asyncOutput.m.Unlock()
		})
		server := &http.Server{
			Addr:    net.JoinHostPort(url.Hostname(), url.Port()),
			Handler: mux,
		}
		if strings.HasSuffix(url.Scheme, "s") && (conf.TLSCertFile != "" && conf.TLSKeyFile != "") {
			server.TLSConfig = &tls.Config{
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}
			server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
			if err = server.ListenAndServeTLS(conf.TLSCertFile, conf.TLSKeyFile); err != nil {
				l.Panic(err.Error())
			}
		} else {
			if err = server.ListenAndServe(); err != nil {
				l.Panic(err.Error())
			}
		}
	} else {
	wloop:
		var o io.Writer
		var err error
		switch conf.Outfile {
		case "1", "-", os.Stdout.Name():
			o = os.Stdout
		case "2", os.Stderr.Name():
			o = os.Stderr
		default:
			o, err = os.OpenFile(conf.Outfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				l.Panic(err.Error())
			}
		}
		asyncOutput.m.Lock()
		switch strings.ToUpper(*format) {
		case "HTML":
			tpl, _, err := temple.FnMap.BuildHTMLTemplate(
				false,
				conf.PageTitle,
				"",
				templates,
			)
			if err != nil {
				l.Panic(err.Error())
			}
			if err := tpl.ExecuteTemplate(o, "index", struct {
				Conf   *configuration
				Output *output
			}{
				conf,
				asyncOutput.o,
			}); err != nil {
				l.Panic(err.Error())
			}
		case "JSON":
			if err := json.NewEncoder(o).Encode(asyncOutput.o); err != nil {
				l.Panic(err.Error())
			}
		case "YML", "YAML":
			fallthrough
		default:
			if err := yaml.NewEncoder(o).Encode(asyncOutput.o); err != nil {
				l.Panic(err.Error())
			}
		}
		asyncOutput.m.Unlock()
		if conf.LoopDelay > 0 {
			time.Sleep(conf.LoopDelay + 1*time.Second)
			goto wloop
		}
	}
}

func logFmts() []string {
	var out []string
	for f := range log.Formats {
		if !strings.Contains(f, "rfc") {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

var defaultIndex string = `
<!doctype html>
<html lang="en">
   <style type="text/css">
      body { background: black !important; }
   </style>
   <meta charset="utf-8">
   <meta http-equiv="refresh" content="60">
   <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
   <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
   <title>{{.Conf.PageTitle}}</title>
   <body>
      <div class="container bg-dark text-white">
         <div class=row> 
            <div class=col>
            <h1>{{.Conf.PageTitle}}</h1>
            </div>
         </div>
         <div class=row>
            <div class=col>
			{{if ne .Output.Failures 0}}
			<div class="alert alert-danger" role="alert">
			{{.Output.Failures}} check(s) have failed.
			</div>
			<table class="table">
			   <thead class="bg-dark text-white">
				  <tr>
					 <th>Category[ID]</th>
					 <th>TotalAttemtps/Status/Expected</th>
					 <th>Error</th>
					 <th>Duration</th>
				  </tr>
			   </thead>
			   <tbody>
	  {{- range .Output.Results}}
	  {{- if .Error}}
				  <tr class="table-danger">
					 <td>{{.Target.Category}}[{{.Target.ID}}]</td>
					 <td>{{- math .Target.RetryAttempts "+" 1 }} / {{- .StatusCode }} / {{.Target.ExpectedStatusCode}}</td>
					 <td>{{.Error}}</td>
					 <td>{{.Timings.Duration}}</td>
				  </tr>
	  {{- end}}
	  {{- end}}
			   </tbody>
			</table>
	  {{- else}}
				  <div class="alert alert-success" role="alert">All is well, all {{len .Output.Results}} services are up.</div>
	  {{- end}}
		 </div>
	  </div>
<div class=row>
   <div class=col>
{{- range .Output.Results}}{{- if not .Error}}
      <a href="#" class="btn btn-success disabled" tabindex="-1" role="button" aria-disabled="true" style="margin-top: 10px; padding: 10px;">{{.Target.Category}}[{{.Target.ID}}]<font color=LightGray>({{.Timings.Duration}})</font></a>
{{- end}}{{- end}}
   </div>
</div>
         <br>
         <div class=row>
            <div class=col>
               <p class=small>{{timestamp}}
                  <br>Total duration: {{.Output.TotalDuration}}
               </p>
            </div>
         </div>
      </div>
   </body>
</html>

`
