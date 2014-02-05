package panda

import (
	"bufio"
	"bytes"
	"code.google.com/p/go.net/proxy"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPMeetingPlace struct {
	TorAddress string
	URL        string
}

const payloadBytes = 1 << 15

func (hmp *HTTPMeetingPlace) Padding() int {
	return payloadBytes
}

func (hmp *HTTPMeetingPlace) attemptExchange(log func(string, ...interface{}), id, message []byte) (*http.Response, []byte, error) {
	serverURL, err := url.Parse(hmp.URL)
	if err != nil {
		return nil, nil, err
	}

	dialer, err := proxy.SOCKS5("tcp", hmp.TorAddress, nil, proxy.Direct)
	if err != nil {
		return nil, nil, err
	}

	host := serverURL.Host
	if strings.IndexRune(host, ':') == -1 {
		if serverURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, nil, err
	}
	log("Connecting to %s via Tor", host)
	rawConn, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, nil, err
	}

	var conn net.Conn
	if serverURL.Scheme == "https" {
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName: hostname,
		})
		log("Starting TLS handshake with %s", host)
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			log("TLS handshake to %s failed: %s", host, err)
			return nil, nil, err
		}
		conn = tlsConn
	} else {
		conn = rawConn
	}
	defer conn.Close()

	body := bytes.NewReader(message)
	request, err := http.NewRequest("POST", hmp.URL+"/"+hex.EncodeToString(id), body)
	if err != nil {
		return nil, nil, err
	}

	request.ContentLength = int64(len(message))
	request.Header.Add("Content-Type", "application/octet-stream")

	request.Write(conn)
	log("Request sent to %s. Awaiting reply", host)

	response, err := http.ReadResponse(bufio.NewReader(conn), request)

	if err != nil {
		return nil, nil, err
	}

	var responseBody []byte
	if response.Body != nil {
		r := &io.LimitedReader{R: response.Body, N: payloadBytes + 1}
		responseBody, err = ioutil.ReadAll(r)
	}

	return response, responseBody, err
}

func (hmp *HTTPMeetingPlace) Exchange(log func(string, ...interface{}), id, message []byte, shutdown chan struct{}) ([]byte, error) {
	delay := 15 * time.Second
	for {
		response, body, err := hmp.attemptExchange(log, id, message)
		if err != nil {
			log("PANDA exchange failed. Will try again in %s: %s", delay, err)
			goto Sleep
		}

		switch response.StatusCode {
		case 409:
			return nil, errors.New("The transaction failed because this key has been used recently by two other parties")
		case 204:
			log("PANDA exchange waiting for other party. Will try again in %s", delay)
			goto Sleep
		case 200:
			if len(body) > payloadBytes {
				return nil, errors.New("Reply from server is too large")
			}
			return body, nil
		default:
			log("Request resulted in unexpected HTTP status %d. Will try again in %s", response.StatusCode, delay)
		}

	Sleep:
		select {
		case <-shutdown:
			return nil, ShutdownErr
		case <-time.After(delay):
			delay *= 2
			if delay > time.Hour {
				delay = time.Hour
			}
		}
	}

	panic("unreachable")
}
