package panda

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"appengine"
	"appengine/datastore"
)

func init() {
	http.HandleFunc("/exchange/", Exchange)
}

const bodyLimit = 1<<17
const defaultLifetime = 5 * 24 * time.Hour

type Posting struct {
	Time time.Time
	A, B []byte
}

func (p Posting) Expired() bool {
	return p.Time.Add(defaultLifetime).Before(time.Now())
}

func Exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Bad method", 405)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/exchange/") {
		http.Error(w, "Bad URL path", 500)
		return
	}

	tagHex := r.URL.Path[10:]
	tag, err := hex.DecodeString(tagHex)
	if err != nil || len(tag) != 32 {
		http.Error(w, "Malformed tag", 400)
		return
	}

	input := &io.LimitedReader{R: r.Body, N: bodyLimit + 1}
	body, err := ioutil.ReadAll(input)
	r.Body.Close()
	if err != nil {
		http.Error(w, "Error reading body", 400)
		return
	}
	if len(body) == 0 {
		http.Error(w, "Empty body", 400)
		return
	}
	if len(body) > bodyLimit {
		http.Error(w, "Body too large", 413)
		return
	}

	c := appengine.NewContext(r)
	dsKey := datastore.NewKey(c, "Posting", hex.EncodeToString(tag), 0, nil)
	var other []byte
	var contended bool
	var created bool
	err = datastore.RunInTransaction(c, func(c appengine.Context) error {
		var p Posting
		err := datastore.Get(c, dsKey, &p)
		if err == datastore.ErrNoSuchEntity || err == nil && p.Expired() {
			// The posting is new or has expired.
			p = Posting{
				Time: time.Now(),
				A:    body,
			}
			_, err := datastore.Put(c, dsKey, &p)
			created = true
			return err
		}
		if err != nil {
			return err
		}
		if len(p.B) > 0 {
			if bytes.Equal(p.A, body) {
				other = p.B
			} else if bytes.Equal(p.B, body) {
				other = p.A
			} else {
				contended = true
			}
			return nil
		}
		if bytes.Equal(p.A, body) {
			return nil
		}
		p.B = body
		other = p.A
		_, err = datastore.Put(c, dsKey, &p)
		return err
	}, nil)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from transaction: %s\n", err)
		http.Error(w, "Internal error", 500)
		return
	}

	if created {
		maybeGarbageCollect(c)
	}

	if contended {
		http.Error(w, "Tag collision", 409)
		return
	}

	if len(other) == 0 {
		http.Error(w, "Request recorded", 204)
		return
	}

	w.Header().Set("Content-Type", "application/binary")
	w.Header().Set("Content-Length", strconv.Itoa(len(other)))
	w.Write(other)
}

func maybeGarbageCollect(c appengine.Context) {
	var randByte [1]byte
	_, err := io.ReadFull(rand.Reader, randByte[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading random byte: %s\n", err)
		return
	}

	if randByte[0] >= 2 {
		return
	}

	// Every one in 128 insertions we'll clean out expired postings.
	q := datastore.NewQuery("Posting").Order("-Time").Limit(256)
	var toDelete []*datastore.Key
	for t := q.Run(c); ; {
		var p Posting
		key, err := t.Next(&p)
		if err == datastore.Done {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error from query: %s\n", err)
			break
		}
		if !p.Expired() {
			break
		}
		toDelete = append(toDelete, key)
	}
	if err := datastore.DeleteMulti(c, toDelete); err != nil {
		fmt.Fprintf(os.Stderr, "Error from multi-delete: %s\n", err)
	}
}
