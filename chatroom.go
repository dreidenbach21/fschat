package main

import (
	"fmt"
	"log"
	"net/http"

	//for the passwords

	//"github.com/gorilla/mux"

	"github.com/gorilla/websocket"
)

var activeUsers = make(map[string]*websocket.Conn)
var clients = make(map[*websocket.Conn]bool) // connected clients
var broadcast = make(chan Message)           // broadcast channel
var upgrader = websocket.Upgrader{}

// Message : messages
type Message struct {
	// Name    string `json:"name"`
	Message string `json:"message"`
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Upgrade initial GET request to a websocket
	fmt.Println("handling connections")
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("passed err 1")
	// Make sure we close the connection when the function returns
	defer ws.Close()

	// em := getEmail(w, r)

	// if val, ok := activeUsers[em]; !ok {
	// 	//do something here
	// 	clients[ws] = true // registering the client
	// 	activeUsers[em] = ws
	// 	_ = val
	// }
	clients[ws] = true

	for {
		var msg Message
		// Read in a new message as JSON and map it to a Message object
		err := ws.ReadJSON(&msg)
		//fmt.Println(msg.Message)
		if err != nil {
			fmt.Printf("error: %v", err)
			fmt.Println("handdle connections error")
			delete(clients, ws)
			break
		}
		fmt.Println("passed err 2")

		msg.Message = getName(w, r) + msg.Message

		fmt.Println(msg.Message)
		// Send the newly received message to the broadcast channel
		broadcast <- msg
		// refreshJWT(w, r)
	}

}

func handleMessages() {
	var did = 1
	var dod = 1
	for {
		fmt.Println("handling messages")
		// Grab the next message from the broadcast channel
		msg := <-broadcast
		// Send it out to every client that is currently connected
		//fmt.Println(msg.Message)
		fmt.Println("outer: ", did)
		did++

		fmt.Println(clients)
		for client := range clients {
			fmt.Println("inner: ", dod)
			dod++
			err := client.WriteJSON(msg)
			if err != nil {
				log.Printf("error: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}
