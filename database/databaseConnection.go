package database

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
	"time"
)
import "github.com/joho/godotenv"

func DBinstance() *mongo.Client {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("error loading the .env file")
	}
	mongoDB := os.Getenv("MONGO_URL")
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoDB))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("connected to mongodb")
	return client
}

var Client *mongo.Client = DBinstance()

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("cluster0").Collection(collectionName)
	return collection
}
