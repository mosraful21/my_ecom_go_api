package database

import (
	"database/sql"
	"fmt"
	"my_ecom_api/config"

	_ "github.com/go-sql-driver/mysql"
)

func Connect(c *config.Config) (*sql.DB, error) {

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		c.DBUser,
		c.DBPassword,
		c.DBHost,
		c.DBPort,
		c.DBName,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println("Database Open Error:", err)
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		fmt.Println("Database Connection Error:", err)
		return nil, err
	}

	fmt.Println("Database Connected")

	return db, nil
}
