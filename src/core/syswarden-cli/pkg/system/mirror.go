package system

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

var StandardMirrors = map[string]string{
	"GitHub":   "https://raw.githubusercontent.com/",
	"Codeberg": "https://codeberg.org/",
}

// SelectFastestMirror benchmarks mirrors and selects the fastest one
func SelectFastestMirror() (string, error) {
	fmt.Println("[INFO] Benchmarking mirrors...")
	
	fastestTime := time.Hour
	fastestURL := StandardMirrors["Codeberg"] // Default fallback

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for name, url := range StandardMirrors {
		fmt.Printf("Connecting to %s... ", name)
		
		start := time.Now()
		req, _ := http.NewRequestWithContext(context.Background(), "HEAD", url, nil)
		resp, err := client.Do(req)
		
		if err == nil && resp.StatusCode == 200 {
			duration := time.Since(start)
			fmt.Printf("%d ms\n", duration.Milliseconds())
			if duration < fastestTime {
				fastestTime = duration
				fastestURL = url
			}
		} else {
			fmt.Println("FAIL")
		}
	}

	fmt.Printf("[INFO] Selected Mirror: %s\n", fastestURL)
	return fastestURL, nil
}
