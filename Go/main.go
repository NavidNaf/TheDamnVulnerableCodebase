package main

import (
    "archive/zip"
    "database/sql"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    _ "github.com/go-sql-driver/mysql" // MySQL driver
)

var db *sql.DB

// Vulnerable endpoint for SQL Injection
// exploitation: http://localhost:8080/user?id=1%20OR%201=1 (URL-encoded payload)
func userHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("id")
    query := fmt.Sprintf("SELECT id, name, email FROM users WHERE id = %s;", userID) // SQL Injection vulnerability

    rows, err := db.Query(query)
    if err != nil {
        http.Error(w, fmt.Sprintf("query error: %v", err), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    for rows.Next() {
        var id int
        var name, email string
        if scanErr := rows.Scan(&id, &name, &email); scanErr != nil {
            http.Error(w, fmt.Sprintf("scan error: %v", scanErr), http.StatusInternalServerError)
            return
        }
        fmt.Fprintf(w, "id=%d name=%s email=%s\n", id, name, email)
    }
}

// Vulnerable endpoint for reflected XSS
// exploitation: http://localhost:8080/greet?name=<script>alert('XSS')</script> (URL-encoded payload)
func greetHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    tmpl := `<h1>Hello, %s</h1>` // XSS vulnerability
    fmt.Fprintf(w, tmpl, name)
}

// Vulnerable endpoint for command injection
// Reference: https://snyk.io/blog/understanding-go-command-injection-vulnerabilities/
// exploitation: http://localhost:8080/run?cmd=ls%20-al%20/ (URL-encoded command)
func runHandler(w http.ResponseWriter, r *http.Request) {
    command := r.URL.Query().Get("cmd")
    output, err := exec.Command("sh", "-c", command).CombinedOutput() // Command Injection vulnerability
    if err != nil {
        http.Error(w, fmt.Sprintf("command error: %v\noutput: %s", err, output), http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "output:\n%s", output)
}

// The following vulnerabilities are taken from the following resource:
// https://pentesterlab.com/blog/6-easy-bugs-golang-source-code-review

// Directory traversal via filepath.Clean
// exploitation: http://localhost:8080/file?name=../../etc/passwd (URL-encoded payload)
func fileHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    path := fmt.Sprintf("/files/%s", name) // Potential directory traversal vulnerability
    http.ServeFile(w, r, path)
}

// Weak Random Generation using math/rand
// exploitation: http://localhost:8080/random (no parameters needed)
func randomHandler(w http.ResponseWriter, r *http.Request) {
    randomValue := fmt.Sprintf("%d", rand.Int()) // Weak random generation vulnerability
    fmt.Fprintf(w, "Random Value: %s", randomValue)
}

// Hostname Validation with strings.HasSuffix
// exploitation: http://localhost:8080/hostname?host=example.com.evil.com (URL-encoded payload)
func hostnameHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    if strings.HasSuffix(host, ".example.com") { // Hostname validation vulnerability
        fmt.Fprintf(w, "Valid host: %s", host)
    } else {
        http.Error(w, "Invalid host", http.StatusBadRequest)
    }
}   

// Timing Side-Channel Attacks in String Comparison
// exploitation: http://localhost:8080/compare?input=secret (URL-encoded payload)
// Note: to exploit this vulnerability, an attacker would need to measure the response time for different inputs to infer the correct secret value.
func compareHandler(w http.ResponseWriter, r *http.Request) {
    input := r.URL.Query().Get("input")
    secret := dbPassword // Secret loaded from config.go

    if input == secret { // Vulnerable to timing attacks
        fmt.Fprintf(w, "Access granted")
    } else {
        http.Error(w, "Access denied", http.StatusUnauthorized)
    }
}   

// ZIP Slip via Archive Extraction
// directly taken from the resource 
func extractZip(src, dest string) error {
    r, err := zip.OpenReader(src)
    // Note: the zip.OpenReader function does not perform any validation on the file paths within the ZIP archive, which can lead to a ZIP Slip vulnerability if an attacker crafts a malicious ZIP file with paths that traverse directories (e.g., "../../etc/passwd").
    if err != nil {
        return err
    }
    defer r.Close()
    
    // The following loop iterates over the files in the ZIP archive and extracts them to the specified destination directory.
    for _, f := range r.File {
        // Dangerous: trusting f.Name directly!
        path := filepath.Join(dest, f.Name)
        
        if f.FileInfo().IsDir() {
            os.MkdirAll(path, f.Mode())
            continue
        }
        
        rc, err := f.Open()
        if err != nil {
            return err
        }
        defer rc.Close()
        
        outFile, err := os.Create(path)
        if err != nil {
            return err
        }
        defer outFile.Close()
        
        _, err = io.Copy(outFile, rc)
        if err != nil {
            return err
        }
    }
    return nil
}

// Vulnerable ZIP extraction endpoint
// exploitation: http://localhost:8080/extract?src=/tmp/evil.zip&dest=/tmp/out (URL-encoded payload)
func extractHandler(w http.ResponseWriter, r *http.Request) {
    src := r.URL.Query().Get("src")
    dest := r.URL.Query().Get("dest")
    if src == "" || dest == "" {
        http.Error(w, "missing src or dest query parameter", http.StatusBadRequest)
        return
    }

    if err := extractZip(src, dest); err != nil {
        http.Error(w, fmt.Sprintf("extract error: %v", err), http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "Extracted %s to %s", src, dest)
}

func main() {
    var err error
    db, err = sql.Open("mysql", "user:password@/dbname") // Hardcoded credentials
    if err != nil {
        log.Fatal(err)
    }

    http.HandleFunc("/user", userHandler)
    http.HandleFunc("/greet", greetHandler)
    http.HandleFunc("/run", runHandler)
    http.HandleFunc("/file", fileHandler)
    http.HandleFunc("/random", randomHandler)
    http.HandleFunc("/hostname", hostnameHandler)
    http.HandleFunc("/compare", compareHandler)
    http.HandleFunc("/extract", extractHandler)

    log.Println("Server running on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
