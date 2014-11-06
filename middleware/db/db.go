/*
A high level package for interacting with the underlying SQL database and doing
necessary tasks.
*/
package db

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func Open(driver, dataSourceName string) error {
	var err error
	db, err = sql.Open(driver, dataSourceName)
	return err
}
