package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Github user info
type User struct {
	Name        string `json:"name"`
	PublicRepos int    `json:"public_repos"`
}

func userInfo(login string) (*User, error) {
	//HTTP CALL
	url := fmt.Sprintf("https://api.github.com/users/%s", login)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Decode the JSON
	user := &User{} //create empty user object
	responseDecoder := json.NewDecoder(response.Body)
	if err := responseDecoder.Decode(user); err != nil {
		return nil, err
	}
	return user, nil
}
func main() {
	user, err := userInfo("tebeka")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(user)
}
