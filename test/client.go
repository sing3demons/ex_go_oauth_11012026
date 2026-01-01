package main

import (
	"fmt"
	"net/http"
	"sync"
)

func main() {
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
	test()
}

func test() {
	// Client code would go here
	wg := sync.WaitGroup{}
	concur := 1000
	wg.Add(concur)

	// 100 concurrent API calls
	for i := 0; i < concur; i++ {
		go func() {
			defer wg.Done()
			if err := callApi(&wg); err != nil {
				fmt.Println("Error calling API:", err)
			}
		}()
	}

	wg.Wait()
	fmt.Println("All API calls completed")
}

func callApi(wg *sync.WaitGroup) error {
	httpClient := &http.Client{}
	resp, err := httpClient.Get("http://localhost:8081/test")
	if err != nil {
		return err
	}
	resp.Body.Close()

	fmt.Println("Status Code:", resp.StatusCode)
	return nil
}
