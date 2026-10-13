package utils

import (
	"net/http"
	"strconv"
	"strings"
)

type QueryParams struct {
	Search string

	Page   int
	Limit  int
	Offset int

	Sort  string
	Order string
}

type QueryBuilder struct {
	Conditions []string
	Args       []interface{}
}

type Pagination struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

func GetQueryParams(r *http.Request, defaultLimit int) QueryParams {
	q := r.URL.Query()

	page := 1
	limit := defaultLimit

	if value := q.Get("page"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if value := q.Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	if limit > 100 {
		limit = 100
	}

	return QueryParams{
		Search: strings.TrimSpace(q.Get("search")),
		Page:   page,
		Limit:  limit,
		Offset: (page - 1) * limit,
		Sort:   strings.TrimSpace(q.Get("sort")),
		Order:  strings.TrimSpace(q.Get("order")),
	}
}

func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{
		Conditions: make([]string, 0),
		Args:       make([]interface{}, 0),
	}
}

func (q *QueryBuilder) Add(condition string, args ...interface{}) {
	q.Conditions = append(q.Conditions, condition)
	q.Args = append(q.Args, args...)
}

func (q *QueryBuilder) Where() string {
	if len(q.Conditions) == 0 {
		return ""
	}

	return " WHERE " + strings.Join(q.Conditions, " AND ")
}

func GetOrder(
	sort string,
	order string,
	allowed map[string]string,
	defaultSort string,
) string {

	column, ok := allowed[sort]

	if !ok {
		column = defaultSort
	}

	direction := "DESC"

	if strings.ToLower(order) == "asc" {
		direction = "ASC"
	}

	return " ORDER BY " + column + " " + direction
}

func CalculatePagination(
	page int,
	limit int,
	total int,
) Pagination {

	totalPages := 0

	if total > 0 {
		totalPages = (total + limit - 1) / limit
	}

	return Pagination{
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: totalPages,
	}
}
