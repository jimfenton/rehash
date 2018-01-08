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
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"log"
	"net/http"
)

type hasher struct {
	Key []byte
}

func (ha hasher) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request) {

	if r.Method != "POST" {
		w.Header().Add("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	hm, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Read error: ", err)
		return
	}

	h, err := base64.StdEncoding.DecodeString(string(hm))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Input hash base64 decode error", err)
		return
	}

	h = pbkdf2.Key(h, ha.Key, 1, 32, sha256.New)
	h2 := base64.StdEncoding.EncodeToString(h)
	fmt.Fprintf(w, "%s\n", h2)

}

func main() {
	var hr hasher

	/* As a proof-of-concept, rehash reads the private key from a file, /etc/rehash.key. The secrecy
	   of this value is obviously critical to the security of rehash. In practice other facilities,
	   such as key vaults, should be used to provide higher security. Since these mechanisms are often
	   platform-dependent, the more simple-minded approach is used here.
	*/

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
