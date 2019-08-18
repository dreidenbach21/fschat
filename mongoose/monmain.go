package main

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"os"
// 	"time"

// 	"go.mongodb.org/mongo-driver/bson"
// 	"go.mongodb.org/mongo-driver/mongo"
// 	"go.mongodb.org/mongo-driver/mongo/options"
// )

// // You will be using this Trainer type later in the program
// type User struct {
// 	Name     string
// 	Age      int
// 	Email    string
// 	Password string
// }

func main() {

	// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// 	defer cancel() //what ever the /test part is is waht opens up teh starting call to db
	// 	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
	// 		"mongodb+srv://dreidenbach:Reidenbach1@fschat-gipdg.mongodb.net/test?w=majority",
	// 	))
	// 	fmt.Println("pre ping")
	// 	err = client.Ping(ctx, nil)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		os.Exit(1)
	// 	}

	// 	fmt.Println("Connected to MongoDB!")

	// 	collection := client.Database("test1").Collection("Users")

	// 	ash := User{"Ash", 10, "Pallet Town", "dog"}
	// 	misty := User{"Misty", 10, "Cerulean City", "dog"}
	// 	brock := User{"Brock", 15, "Pewter City", "dog"}

	// 	insertResult, err := collection.InsertOne(context.TODO(), ash)

	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	fmt.Println("Inserted a single document: ", insertResult.InsertedID)
	// 	//To insert multiple documents at a time, the collection.InsertMany() method will take a slice of objects:

	// 	trainers := []interface{}{misty, brock}

	// 	insertManyResult, err := collection.InsertMany(context.TODO(), trainers)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	fmt.Println("Inserted multiple documents: ", insertManyResult.InsertedIDs)

	// 	filter := bson.D{{Key: "name", Value: "Ash"}}

	// 	update := bson.D{
	// 		{"$inc", bson.D{
	// 			{"age", 1},
	// 		}},
	// 	}

	// 	updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	fmt.Printf("Matched %v documents and updated %v documents.\n", updateResult.MatchedCount, updateResult.ModifiedCount)

	// 	err = client.Disconnect(context.TODO())

	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	fmt.Println("Connection to MongoDB closed.")
}
