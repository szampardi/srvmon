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
	"sync"
	"sync/atomic"
	"time"

	"github.com/szampardi/hermes"
)

type Check struct {
	Target
	StatusCode int           `yaml:"StatusCode,omitempty"`
	Duration   time.Duration `yaml:"Duration,omitempty"`
	Error      string        `yaml:"Error,omitempty"`
}

type output struct {
	Results  map[string]*Check `yaml:"Results,omitempty"`
	Duration time.Duration     `yaml:"Duration,omitempty"`
	Failures uint32            `yaml:"Failures,omitempty"`
	Total    int               `yaml:"Total,omitempty"`
}

func (R *output) checkAllWorker(s *sync.Mutex, wg *sync.WaitGroup, tgt Target) {
	y := new(Check)
	y.Target = tgt
	resp, dur, err := y.check()
	if err != nil {
		atomic.AddUint32(&R.Failures, 1)
		y.Error = err.Error()
		if conf.Alerts != "" {
			l.Warningf("check for %s failed, sending alert..", tgt.ID)
			post := hermes.POST{
				Emoji: ":warning:",
				Text:  fmt.Sprintf("*WARNING*: `%s[%s]` healthcheck (`%s`) failed\nHTTP code / expected: *%d / %d*\nError: `%s`\n", y.Category, y.ID, y.URL, y.StatusCode, y.ExpectedStatusCode, y.Error),
			}
			j, err := json.Marshal(post)
			if err == nil {
				_, err := hermes.Send(bytes.NewBuffer(j))
				if err != nil {
					l.Critical(err.Error())
				}
			}
		}
	}
	if resp != nil {
		y.StatusCode = resp.StatusCode
	}
	y.Duration = dur
	s.Lock()
	R.Results[y.ID] = y
	R.Total++
	s.Unlock()
	wg.Done()
}

func checkAll(ts []Target, concurrency ...int) *output {
	o := new(output)
	o.Results = make(map[string]*Check)
	start := time.Now()
	wg := &sync.WaitGroup{}
	s := &sync.Mutex{}

	batch := 4
	if len(concurrency) > 0 {
		batch = concurrency[0]
	}
	for i := 0; i < len(ts); i += batch {
		j := i + batch
		if j > len(ts) {
			j = len(ts)
		}
		for _, tgt := range ts[i:j] {
			wg.Add(1)
			go o.checkAllWorker(s, wg, tgt)
		}
		wg.Wait()
	}
	o.Duration = time.Since(start)
	return o
}

func (t *Target) check() (*http.Response, time.Duration, error) {
	if t.ExpectedStatusCode == 0 {
		t.ExpectedStatusCode = 200
	}
	if t.Method == "" {
		t.Method = http.MethodGet
	}
	if t.RetryAttempts == 0 {
		t.RetryAttempts = conf.RetryAttempts
	}
	if t.clt == nil {
		t.clt = httpClient(conf.Timeout, t.DNSAddress, t.TLSSkipVerify)
	}
	var r *http.Response
	var err error
	start := time.Now()
	ctr := 0
attempt:
	ctr++
	l.Debugf("check for %s initiating, attempt %d of %d", t.ID, ctr, t.RetryAttempts+1)
	switch t.Method {
	case http.MethodGet:
		r, err = t.clt.Get(t.URL)
	case http.MethodHead:
		r, err = t.clt.Head(t.URL)
	case http.MethodPost:
		r, err = t.clt.Post(t.URL, "", nil)
	default:
		req, err := http.NewRequest(t.Method, t.URL, nil)
		if err != nil {
			return nil, 0, err
		}
		r, err = t.clt.Do(req)
	}
	took := time.Since(start)
	if err != nil {
		if (t.RetryAttempts > 0) && (ctr <= t.RetryAttempts) {
			l.Criticalf("check for %s failed, retrying (%d/%d) in %s", t.ID, ctr, t.RetryAttempts, conf.RetryDelay)
			time.Sleep(conf.RetryDelay)
			goto attempt
		}
		return nil, took, err
	}
	if r != nil && r.StatusCode != t.ExpectedStatusCode {
		err = fmt.Errorf("status code %d does not match expected %d", r.StatusCode, t.ExpectedStatusCode)
	}
	defer t.clt.CloseIdleConnections()
	l.Debugf("check for %s completed successfully", t.ID)
	return r, took, err
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
