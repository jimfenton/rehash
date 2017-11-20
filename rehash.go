/*

rehash.go - Prototype service for keyed hashing

Copyright (c) 2017 Jim Fenton
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"log"
	"net/http"
)

type hasher struct {
	Key []byte
}

type hashMsg struct {
	Hash64 string `json:"hash"` //in base64 format
}

func (ha hasher) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request) {

	var hm hashMsg

	if r.Method != "POST" {
		w.Header().Add("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Read error: ", err)
		return
	}
	err = json.Unmarshal(body, &hm)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Error decoding hash json:", err)
		return
	}

	h, err := base64.StdEncoding.DecodeString(hm.Hash64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Input hash base64 decode error", err)
		return
	}

	h = pbkdf2.Key(h, ha.Key, 1, 32, sha256.New)
	h2 := base64.StdEncoding.EncodeToString(h)
	fmt.Fprintf(w, "{\"rehash\": %q}\n", h2)

}

func main() {
	var hr hasher
	dat, err := ioutil.ReadFile("/etc/rehash.key")
	if err != nil {
		log.Fatal(err)
	}

// Key is in hexadecimal, 64 hex characters

	hr.Key, err = hex.DecodeString(string(dat)[0:64])
	if err != nil {
		log.Fatal(err)
		}

	log.Fatal(http.ListenAndServe(":8888", hr))
}
