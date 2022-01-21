package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/szampardi/hermes"
)

type (
	Timings struct {
		Start time.Time     `json:"Start,omitempty" yaml:"Start,omitempty"`
		End   time.Time     `json:"End,omitempty" yaml:"End,omitempty"`
		Last  time.Duration `json:"Duration,omitempty" yaml:"Duration,omitempty"`
		Total time.Duration `json:"TotalDuration,omitempty" yaml:"TotalDuration,omitempty"`
	}
	Result struct {
		*Target
		httpResponse *http.Response `json:"-" yaml:"-"`
		parsedURL    *url.URL       `json:"-" yaml:"-"`
		StatusCode   int            `json:"StatusCode,omitempty" yaml:"StatusCode,omitempty"`
		Timings      *Timings       `json:"Timings,omitempty" yaml:"Timings,omitempty"`
		Error        error          `json:"Error,omitempty" yaml:"Error,omitempty"`
		Attempts     uint32         `json:"Attempts" yaml:"Attempts"`
	}
)

type output struct {
	Results       map[string]map[string]*Result `json:"Results,omitempty" yaml:"Results,omitempty"`
	TotalDuration time.Duration                 `json:"TotalDuration,omitempty" yaml:"TotalDuration,omitempty"`
	Failures      uint32                        `json:"Failures,omitempty" yaml:"Failures,omitempty"`
}

func (t *Target) check() (Result, error) {
	if t.ExpectedStatusCode == 0 {
		t.ExpectedStatusCode = 200
	}
	if t.RetryAttempts == 0 {
		t.RetryAttempts = conf.RetryAttempts
	}
	tmo := conf.Timeout
	if t.Timeout != 0 {
		tmo = t.Timeout
	}
	start := time.Now()
	r := Result{
		Target: t,
		Timings: &Timings{
			Start: start,
		},
	}
	var err error
	r.parsedURL, err = url.Parse(r.URL)
	if err != nil {
		return r, err
	}
	if r.Method == "" {
		switch s := r.parsedURL.Scheme; {
		case s == "" || strings.Contains(strings.ToLower(s), "http"):
			r.Method = http.MethodGet
		default:
			r.Method = s
		}
	}
	atomic.StoreUint32(&r.Attempts, 0)
attempt:
	att := atomic.AddUint32(&r.Attempts, 1)
	switch {
	case strings.Contains(r.Method, "tcp") || strings.Contains(r.Method, "udp") || strings.Contains(r.Method, "ip") || strings.Contains(r.Method, "unix"):
		if err := r.netCheck(tmo); err != nil {
			return r, err
		}
	default:
		if err := r.httpCheck(tmo); err != nil {
			return r, err
		}
	}
	if r.Error != nil {
		if (r.RetryAttempts > 0) && (int(att) <= r.RetryAttempts) {
			l.Criticalf("check for %s[%s] failed, retrying (%d/%d) in %s", r.Category, r.ID, att, r.RetryAttempts, conf.RetryDelay)
			time.Sleep(conf.RetryDelay)
			goto attempt
		}
		return r, nil
	}
	l.Noticef("check for %s[%s] completed in %s (attempt %d/%d)", r.Category, r.ID, r.Timings.Total, att, r.RetryAttempts)
	return r, nil
}

func (r *Result) netCheck(timeout time.Duration) error {
	l.Debugf("starting %s check for %s[%s] (%d/%d)", r.Method, r.Category, r.ID, atomic.LoadUint32(&r.Attempts), r.RetryAttempts+1)
	var c net.Conn
	c, r.Error = net.DialTimeout(r.Method, r.parsedURL.Host, timeout)
	r.Timings.End = time.Now()
	r.Timings.Last = r.Timings.End.Sub(r.Timings.Start)
	r.Timings.Total = r.Timings.Total + r.Timings.Last
	if r.Error == nil {
		r.StatusCode = 200
		if c != nil {
			return c.Close()
		}
	}
	r.StatusCode = -1
	return r.Error
}

func (r *Result) httpCheck(timeout time.Duration) error {
	l.Debugf("starting http/s check for %s[%s] (%d/%d)", r.Category, r.ID, atomic.LoadUint32(&r.Attempts), r.RetryAttempts+1)
	if r.Target.httpClient == nil {
		r.Target.httpClient = httpClient(timeout, r.Target.DNSAddress, r.Target.TLSSkipVerify)
	}
	switch m := strings.ToUpper(r.Method); m {
	case http.MethodGet:
		r.httpResponse, r.Error = r.httpClient.Get(r.URL)
	case http.MethodHead:
		r.httpResponse, r.Error = r.httpClient.Head(r.URL)
	case http.MethodPost:
		r.httpResponse, r.Error = r.httpClient.Post(r.URL, "", nil)
	default:
		req, err := http.NewRequest(m, r.URL, nil)
		if err != nil {
			return err
		}
		r.httpResponse, r.Error = r.httpClient.Do(req)
	}
	r.Timings.End = time.Now()
	r.Timings.Last = r.Timings.End.Sub(r.Timings.Start)
	if r.httpResponse != nil {
		r.StatusCode = r.httpResponse.StatusCode
		defer r.httpResponse.Body.Close()
	}
	go r.httpClient.CloseIdleConnections()
	if r.httpResponse != nil && r.httpResponse.StatusCode != r.ExpectedStatusCode && r.Error == nil {
		switch {
		case r.httpResponse.StatusCode > 399 && r.httpResponse.StatusCode < 500:
			atomic.StoreUint32(&r.Attempts, uint32(r.RetryAttempts+1))
			fallthrough
			/*
				buf := new(bytes.Buffer)
				_, err := io.Copy(buf, r.httpResponse.Body)
				if err != nil {
					l.Criticalf("error reading response body: %s", err)
				}
				r.Error = fmt.Errorf("status code %d: %s", r.StatusCode, buf.String())
			*/
		default:
			r.Error = fmt.Errorf("status code %d does not match expected %d", r.StatusCode, r.ExpectedStatusCode)
		}
	}
	return nil
}

func (R *output) worker(s *sync.Mutex, wg *sync.WaitGroup, awg *sync.WaitGroup, tgt *Target) {
	y, err := tgt.check()
	s.Lock()
	R.Results[y.Category][y.ID] = &y
	s.Unlock()
	wg.Done()
	if err == nil && y.Error != nil {
		atomic.AddUint32(&R.Failures, 1)
		// skip for malformed requests
		if y.Timings.Last > -1 && conf.Alerts != "" {
			awg.Add(1)
			defer awg.Done()
			l.Warningf("check for %s failed, sending alert..", tgt.ID)
			post := hermes.POST{
				Emoji: ":warning:",
				Text:  fmt.Sprintf("*WARNING*: `%s[%s]` healthcheck (`%s`) failed\nHTTP code / expected: *%d / %d*\nError: `%s`\n", y.Category, y.ID, y.URL, y.StatusCode, y.ExpectedStatusCode, y.Error),
			}
			j, err := json.Marshal(post)
			if err == nil {
				_, err := hermes.Send(bytes.NewBuffer(j))
				if err != nil {
					l.Criticalf("could not send alert for %s[%s]: %s", y.Category, y.ID, err)
				}
			} else {
				l.Criticalf("could not send alert for %s[%s]: %s", y.Category, y.ID, err)
			}
		}
	}
	if err != nil {
		l.Criticalf("unable to execute check for %s[%s]: %s", y.Category, y.ID, err)
	}
}

func check(ts []*Target, maxConcurrentRoutines ...int) *output {
	o := new(output)
	o.Results = make(map[string]map[string]*Result)
	if len(ts) < 1 {
		return o
	}
	wg := &sync.WaitGroup{}
	alertswg := &sync.WaitGroup{}
	s := &sync.Mutex{}
	max := runtime.NumCPU()
	if len(maxConcurrentRoutines) > 0 && maxConcurrentRoutines[0] > 0 {
		max = maxConcurrentRoutines[0]
	}
	start := time.Now()
	for i := 0; i < len(ts); i += max {
		j := i + max
		if j > len(ts) {
			j = len(ts)
		}
		for _, tgt := range ts[i:j] {
			if tgt.Category == "" {
				tgt.Category = tgt.Method
			}
			if tgt.Category == "" {
				tgt.Category = "uncategorized"
			}
			if _, ok := o.Results[tgt.Category]; !ok {
				o.Results[tgt.Category] = make(map[string]*Result)
			}
			wg.Add(1)
			go o.worker(s, wg, alertswg, tgt)
		}
		wg.Wait()
	}
	o.TotalDuration = time.Since(start)
	if o.Failures == 0 {
		return o
	}
	l.Debugf("finish sending any alerts..")
	alertswg.Wait()
	return o
}

func netResolver(network, address string, timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, network, address)
		},
	}
}

func httpClient(timeout time.Duration, DNSAddress string, TLSSkipVerify bool) *http.Client {
	tlscfg := &tls.Config{
		Rand:               rand.Reader,
		InsecureSkipVerify: TLSSkipVerify,
		MinVersion:         tls.VersionTLS12,
		CurvePreferences:   []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	var h *http.Client
	if DNSAddress == "" {
		h = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlscfg,
				//MaxConnsPerHost:     4,
				//MaxIdleConnsPerHost: 0,
				//	TLSHandshakeTimeout:   10 * time.Second,
				//	ResponseHeaderTimeout: 10 * time.Second,
				//	ExpectContinueTimeout: 1 * time.Second,
			},
		}
	} else {
		h = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlscfg,
				//MaxConnsPerHost:     4,
				//MaxIdleConnsPerHost: 0,
				//	TLSHandshakeTimeout:   10 * time.Second,
				//	ResponseHeaderTimeout: 10 * time.Second,
				//	ExpectContinueTimeout: 1 * time.Second,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					dialer := &net.Dialer{
						Resolver: netResolver(network, DNSAddress, timeout/2),
					}
					return dialer.DialContext(ctx, network, address)
				},
			},
		}
	}
	return h
}
