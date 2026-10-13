package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"my_ecom_api/config"
	"my_ecom_api/database"
	appredis "my_ecom_api/redis"
	"my_ecom_api/routes"
)

func main() {
	c, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	// Database
	db, err := database.Connect(c)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Redis
	redisClient := appredis.New(c)
	if err := redisClient.Ping(context.Background()); err != nil {
		log.Fatal("Redis connection failed:", err)
	}
	fmt.Println("Redis connected")

	fmt.Println("running on port : " + c.AppPort)
	log.Fatal(http.ListenAndServe(":"+c.AppPort, routes.Setup(db, c, redisClient)))
}
