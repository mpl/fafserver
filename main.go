// Copyright 2016 Mathieu Lonjaret

// fafserver (fire and forget server) starts an HTTPS server on a random port,
// protected by randomly generated username and password for HTTP basic auth, and
// which dies after the specified time.
// It requires the HTTPS cert and key "key.pem" and "cert.pem" in $HOME/keys.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mpl/basicauth"
)

const idstring = "http://golang.org/pkg/http/#ListenAndServe"

var (
	flagHost = flag.String("host", "", "Optional hostname to listen on. The port will still be random.")
	flagDie  = flag.Duration("die", 24*time.Hour, "Die after the specified time.")
	flagHelp = flag.Bool("h", false, "show this help")
)

var (
	rootdir, _ = os.Getwd()
	up         *basicauth.UserPass
)

func usage() {
	fmt.Fprintf(os.Stderr, "\t fafserver \n")
	flag.PrintDefaults()
	os.Exit(2)
}

func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e, ok := recover().(error); ok {
				http.Error(w, e.Error(), http.StatusInternalServerError)
				return
			}
		}()
		title := r.URL.Path
		w.Header().Set("Server", idstring)
		if up.IsAllowed(r) {
			fn(w, r, title)
		} else {
			basicauth.SendUnauthorized(w, r, "simpleHttpd")
		}
	}
}

type sortedFiles []os.FileInfo

func (s sortedFiles) Len() int { return len(s) }

func (s sortedFiles) Less(i, j int) bool {
	return strings.ToLower(s[i].Name()) < strings.ToLower(s[j].Name())
}

func (s sortedFiles) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func sortedDirList(w http.ResponseWriter, f http.File) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre>\n")
	var sdirs sortedFiles
	for {
		dirs, err := f.Readdir(100)
		if err != nil || len(dirs) == 0 {
			break
		}
		sdirs = append(sdirs, dirs...)
	}
	sort.Sort(sdirs)
	for _, d := range sdirs {
		name := d.Name()
		if d.IsDir() {
			name += "/"
		}
		// TODO htmlescape
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", name, name)
	}
	fmt.Fprintf(w, "</pre>\n")
}

// modtime is the modification time of the resource to be served, or IsZero().
// return value is whether this request is now complete.
func checkLastModified(w http.ResponseWriter, r *http.Request, modtime time.Time) bool {
	if modtime.IsZero() {
		return false
	}

	// The Date-Modified header truncates sub-second precision, so
	// use mtime < t+1s instead of mtime <= t to check for unmodified.
	if t, err := time.Parse(http.TimeFormat, r.Header.Get("If-Modified-Since")); err == nil && modtime.Before(t.Add(1*time.Second)) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	w.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	return false
}

// copied from stdlib, and modified to server sorted listing
// name is '/'-separated, not filepath.Separator.
func serveFile(w http.ResponseWriter, r *http.Request, fs http.FileSystem, name string) {
	const indexPage = "/index.html"

	f, err := fs.Open(name)
	if err != nil {
		// TODO expose actual error?
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	d, err1 := f.Stat()
	if err1 != nil {
		// TODO expose actual error?
		http.NotFound(w, r)
		return
	}

	// use contents of index.html for directory, if present
	if d.IsDir() {
		index := name + indexPage
		ff, err := fs.Open(index)
		if err == nil {
			defer ff.Close()
			dd, err := ff.Stat()
			if err == nil {
				name = index
				d = dd
				f = ff
			}
		}
	}

	// Still a directory? (we didn't find an index.html file)
	if d.IsDir() {
		if checkLastModified(w, r, d.ModTime()) {
			return
		}
		sortedDirList(w, f)
		return
	}

	// serverContent will check modification time
	http.ServeContent(w, r, d.Name(), d.ModTime(), f)
}

func myFileServer(w http.ResponseWriter, r *http.Request, url string) {
	dir, file := filepath.Split(filepath.Join(rootdir, url))
	serveFile(w, r, http.Dir(dir), file)
}

func randPort() (int, error) {
	var port int
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return port, err
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return port, fmt.Errorf("could not listen to find random port: %v", err)
	}
	randAddr := listener.Addr().(*net.TCPAddr)
	if err := listener.Close(); err != nil {
		return port, fmt.Errorf("could not close random listener: %v", err)
	}
	return randAddr.Port, nil
}

// randToken genererates (with crypto/rand.Read) and returns a token
// that is the hex version (2x size) of size bytes of randomness.
func randToken(size int) (string, error) {
	buf := make([]byte, size)
	if n, err := rand.Read(buf); err != nil || n != len(buf) {
		return "", fmt.Errorf("failed to get some randomness: %v", err)
	}
	return fmt.Sprintf("%x", buf), nil
}

func initUserPass() {
	user, err := randToken(20)
	if err != nil {
		log.Fatal(err)
	}
	pass, err := randToken(20)
	if err != nil {
		log.Fatal(err)
	}
	up, err = basicauth.New(user + ":" + pass)
	if err != nil {
		log.Fatal(err)
	}
	println("user: " + user)
	println("password: " + pass)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if *flagHelp {
		usage()
	}

	nargs := flag.NArg()
	if nargs > 0 {
		usage()
	}
	initUserPass()
	http.Handle("/", makeHandler(myFileServer))
	port, err := randPort()
	if err != nil {
		log.Fatal(err)
	}
	hostPort := fmt.Sprintf("%v:%v", *flagHost, port)
	t := time.AfterFunc(*flagDie, func() {
		log.Printf("Server lifetime of %v is over, calling it quits now.", *flagDie)
		os.Exit(0)
	})
	println("Starting to listen on: https://" + hostPort)
	fmt.Printf("Server will die in %v\n", *flagDie)
	if err := http.ListenAndServeTLS(
		hostPort,
		filepath.Join(os.Getenv("HOME"), "keys", "cert.pem"),
		filepath.Join(os.Getenv("HOME"), "keys", "key.pem"),
		nil); err != nil {
		t.Stop()
		log.Fatal(err)
	}
}
