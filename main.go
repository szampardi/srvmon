package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/szampardi/hermes"
	log "github.com/szampardi/msg"

	"github.com/szampardi/xprint/temple"
	"gopkg.in/yaml.v3"
)

type (
	configuration struct {
		ConcurrentChecks int           `json:"ConcurrenctChecks,omitempty" yaml:"ConcurrenctChecks,omitempty"`
		Timeout          time.Duration `json:"Timeout,omitempty" yaml:"Timeout,omitempty"`
		RetryDelay       time.Duration `json:"RetryDelay,omitempty" yaml:"RetryDelay,omitempty"`
		RetryAttempts    int           `json:"RetryAttempts,omitempty" yaml:"RetryAttempts,omitempty"`
		Alerts           string        `json:"Alerts,omitempty" yaml:"Alerts,omitempty"`
		PageTitle        string        `json:"PageTitle,omitempty" yaml:"PageTitle,omitempty"`
		Targets          []*Target     `json:"Targets,omitempty" yaml:"Targets,omitempty"`
	}
	Target struct {
		ID                 string        `json:"ID,omitempty" yaml:"ID,omitempty"`
		Category           string        `json:"Category,omitempty" yaml:"Category,omitempty"`
		Method             string        `json:"Method,omitempty" yaml:"Method,omitempty"`
		URL                string        `json:"URL,omitempty" yaml:"URL,omitempty"`
		Headers            []string      `json:"Headers,omitempty" yaml:"Headers,omitempty"`
		ExpectedStatusCode int           `json:"StatusCode,omitempty" yaml:"StatuCcode,omitempty"`
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
	outFile               = flag.String("o", os.Stdout.Name(), "output file")
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
	flag.IntVar(&conf.ConcurrentChecks, "concurrency", 4, "concurrent checks")
	flag.DurationVar(&conf.Timeout, "timeout", 10*time.Second, "checks' timeout")
	flag.DurationVar(&conf.RetryDelay, "delay", 5*time.Second, "delay between failed attempts and retries")
	flag.IntVar(&conf.RetryAttempts, "retry", 1, "generic retry counter for failed checks")
	flag.StringVar(&conf.Alerts, "alerts", os.Getenv("WEBHOOK"), "URL to POST alerts to")
	flag.StringVar(&conf.PageTitle, "title", "Status Dashboard", "webpage title")

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
		} else if err := yaml.Unmarshal(b, &conf); err != nil {
			l.Panic(err.Error())
		}
	}

	for _, arg := range flag.Args() {
		tgt := new(Target)
		for i, p := range strings.Split(arg, ",") {
			switch i {
			case 0:
				tgt.ID = p
			case 1:
				tgt.URL = p
			case 2:
				tgt.Category = p
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
		if err := yaml.NewEncoder(os.Stdout).Encode(conf); err != nil {
			l.Panic(err.Error())
		}
		os.Exit(0)
	}
	var o io.Writer
	switch *outFile {
	case "1", "-", os.Stdout.Name():
		o = os.Stdout
	case "2", os.Stderr.Name():
		o = os.Stderr
	default:
		o1, err := os.OpenFile(*outFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			l.Panic(err.Error())
		}
		o = io.MultiWriter(os.Stdout, o1)
	}
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
		if err := tpl.ExecuteTemplate(o, "index", conf); err != nil {
			l.Panic(err.Error())
		}
	case "YML", "YAML":
		if err := yaml.NewEncoder(o).Encode(check(conf.Targets)); err != nil {
			l.Panic(err.Error())
		}
	case "JSON":
		if err := json.NewEncoder(o).Encode(check(conf.Targets)); err != nil {
			l.Panic(err.Error())
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

var defaultIndex string = `{{$results := check .Targets .ConcurrentChecks}}
<!doctype html>
<html lang="en">
   <style type="text/css">
      body { background: black !important; }
   </style>
   <meta charset="utf-8">
   <meta http-equiv="refresh" content="60">
   <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
   <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
   <title>{{.PageTitle}}</title>
   <body>
      <div class="container bg-dark text-white">
         <div class=row> 
            <div class=col>
            <h1>{{.PageTitle}}</h1>
            </div>
         </div>
         <div class=row>
            <div class=col>
			{{if ne $results.Failures 0}}
			<div class="alert alert-danger" role="alert">
			{{.Failures}} check(s) have failed.
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
	  {{- range $results.Results}}
	  {{- if .Error}}
				  <tr class="table-danger">
					 <td>{{.Target.Category}}[{{.Target.ID}}]</td>
					 <td>{{- math .Target.RetryAttempts "+" 1 }} / {{- .StatusCode }} / {{.Target.ExpectedStatusCode}}</td>
					 <td>{{.Error}}</td>
					 <td>{{.Duration}}</td>
				  </tr>
	  {{- end}}
	  {{- end}}
			   </tbody>
			</table>
	  {{- else}}
				  <div class="alert alert-success" role="alert">All is well, all {{len $results.Results}} services are up.</div>
	  {{- end}}
		 </div>
	  </div>
<div class=row>
   <div class=col>
{{- range $results.Results}}{{- if not .Error}}
      <a href="#" class="btn btn-success disabled" tabindex="-1" role="button" aria-disabled="true" style="margin-top: 10px; padding: 10px;">{{.Target.Category}}[{{.Target.ID}}]<font color=LightGray>({{.Timings.Duration}})</font></a>
{{- end}}{{- end}}
   </div>
</div>
         <br>
         <div class=row>
            <div class=col>
               <p class=small>{{timestamp}}
                  <br>Total duration: {{$results.TotalDuration}}
               </p>
            </div>
         </div>
      </div>
   </body>
</html>
`
