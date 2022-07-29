package models

import (
	"context"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"strconv"
)

//goland:noinspection ALL
type DbConn interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, optionsAndArgs ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, optionsAndArgs ...interface{}) pgx.Row
}

type Scanner interface {
	Scan(...interface{}) error
}

func NewDbConn(ctx context.Context, config map[string]any) (DbConn, error) {
	c, err := pgxpool.ParseConfig(config["url"].(string))
	if err != nil {
		return nil, err
	}
	if v, ok := config["max_conns"]; ok {
		conn, err := strconv.Atoi(v.(string))
		if err != nil {
			return nil, err
		}
		c.MaxConns = int32(conn)
	}
	if v, ok := config["min_conns"]; ok {
		conn, err := strconv.Atoi(v.(string))
		if err != nil {
			return nil, err
		}
		c.MinConns = int32(conn)
	}
	return pgxpool.ConnectConfig(ctx, c)
}

func ExecuteSQL(ctx context.Context, db DbConn, sql string, optionsAndArgs ...any) ([]map[string]any, error) {
	rows, err := db.Query(ctx, sql, optionsAndArgs...)
	defer rows.Close()
	if err != nil {
		return nil, err
	}
	fields := rows.FieldDescriptions()
	results := make([]map[string]any, 0)
	for rows.Next() {
		r := make(map[string]any)
		var values []any
		values, err = rows.Values()
		n := len(values)
		for i := 0; i < n; i++ {
			r[string(fields[i].Name)] = values[i]
		}
		results = append(results, r)
	}
	return results, nil
}

func _() {
	_ = ExecuteSQL
}
