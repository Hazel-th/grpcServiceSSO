package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	var storagePath, migrationsPath, migrationsTable string

	flag.StringVar(&storagePath, "storage-path", "", "path to store storage")
	flag.StringVar(&migrationsPath, "migrations-path", "", "path to store migrations")
	flag.StringVar(&migrationsTable, "migrations-table", "migrations", "path to store migrations table")
	flag.Parse()

	if storagePath == "" || migrationsPath == "" {
		panic("invalid arguments")
	}

	m, err := migrate.New("file://"+migrationsPath,
		fmt.Sprintf("sqlite://%s?x-migrations-table=%s", storagePath, migrationsTable),
	)
	if err != nil {
		panic(err)
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("no migrations found")
			return
		}
		panic(err)
	}

	fmt.Println("migrated successfully")
}
