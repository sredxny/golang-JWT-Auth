# golang-JWT-Auth
A basic project made in Go to show how JWT authentication can be implemented in the language

# Installation steps
* Clone repo
* Step into project directory and execute: go get ./...
* go run main.go 

# Usage
## SignIn and get a new JWT token
Endpoint: POST http://localhost:8000/signin
Payload: {"username":"user1","password":"password1"}

## Access Protected route
Endpoint: GET http://localhost:8000/welcome

## Renew token
Endpoint: POST http://localhost:8000/refresh
