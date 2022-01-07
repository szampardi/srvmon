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
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/szampardi/hermes"
)

type (
	Timings struct {
		Start    time.Time     `json:"Start,omitempty" yaml:"Start,omitempty"`
		End      time.Time     `json:"End,omitempty" yaml:"End,omitempty"`
		Duration time.Duration `json:"Duration,omitempty" yaml:"Duration,omitempty"`
	}
	Result struct {
		*Target
		httpResponse *http.Response `json:"-" yaml:"-"`
		StatusCode   int            `json:"StatusCode,omitempty" yaml:"StatusCode,omitempty"`
		Timings      Timings        `json:"Timings,omitempty" yaml:"Timings,omitempty"`
		Error        error          `json:"Error,omitempty" yaml:"Error,omitempty"`
	}
)

type output struct {
	Results       map[string]*Result `json:"Results,omitempty" yaml:"Results,omitempty"`
	TotalDuration time.Duration      `json:"TotalDuration,omitempty" yaml:"TotalDuration,omitempty"`
	Failures      uint32             `json:"Failures,omitempty" yaml:"Failures,omitempty"`
}

func (t *Target) check() (Result, error) {
	if t.ExpectedStatusCode == 0 {
		t.ExpectedStatusCode = 200
	}
	if t.Method == "" {
		t.Method = http.MethodGet
	}
	if t.RetryAttempts == 0 {
		t.RetryAttempts = conf.RetryAttempts
	}
	tmo := conf.Timeout
	if t.Timeout != 0 {
		tmo = t.Timeout
	}
	if t.clt == nil {
		t.clt = httpClient(tmo, t.DNSAddress, t.TLSSkipVerify)
	}
	r := Result{Target: t}
	r.Timings.Start = time.Now()
	ctr := 0
attempt:
	ctr++
	l.Debugf("starting check for %s[%s] (%d/%d)", r.Category, r.ID, ctr, r.RetryAttempts+1)
	switch r.Method {
	case http.MethodGet:
		r.httpResponse, r.Error = r.clt.Get(r.URL)
	case http.MethodHead:
		r.httpResponse, r.Error = r.clt.Head(r.URL)
	case http.MethodPost:
		r.httpResponse, r.Error = r.clt.Post(r.URL, "", nil)
	default:
		req, err := http.NewRequest(r.Method, r.URL, nil)
		if err != nil {
			return r, err
		}
		r.httpResponse, err = r.clt.Do(req)
	}
	r.Timings.End = time.Now()
	r.Timings.Duration = r.Timings.End.Sub(r.Timings.Start)
	if r.httpResponse != nil {
		r.StatusCode = r.httpResponse.StatusCode
		defer r.httpResponse.Body.Close()
	}
	go r.clt.CloseIdleConnections()
	if r.httpResponse != nil && r.httpResponse.StatusCode != r.ExpectedStatusCode && r.Error == nil {
		switch {
		case r.httpResponse.StatusCode > 399 && r.httpResponse.StatusCode < 500:
			ctr = r.RetryAttempts + 1
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
	if r.Error != nil {
		if (r.RetryAttempts > 0) && (ctr <= r.RetryAttempts) {
			l.Criticalf("check for %s[%s] failed, retrying (%d/%d) in %s", r.Category, r.ID, ctr, r.RetryAttempts, conf.RetryDelay)
			time.Sleep(conf.RetryDelay)
			goto attempt
		}
		return r, nil
	}
	l.Noticef("check for %s[%s] completed in %s", r.Category, r.ID, r.Timings.Duration)
	return r, nil
}

func (R *output) worker(s *sync.Mutex, wg *sync.WaitGroup, awg *sync.WaitGroup, tgt *Target) {
	y, err := tgt.check()
	s.Lock()
	R.Results[y.ID] = &y
	s.Unlock()
	wg.Done()
	if err == nil && y.Error != nil {
		atomic.AddUint32(&R.Failures, 1)
		// skip for malformed requests
		if y.Timings.Duration > -1 && conf.Alerts != "" {
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
	o.Results = make(map[string]*Result)
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
