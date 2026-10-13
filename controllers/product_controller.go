package controllers

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"my_ecom_api/config"
	"my_ecom_api/middleware"
	"my_ecom_api/models"
	"my_ecom_api/utils"
)

type ProductController struct {
	DB  *sql.DB
	Cfg *config.Config
}

const productSelect = `
	SELECT
		id,
		name,
		description,
		price,
		stock,
		status,
		image,
		created_at,
		updated_at
	FROM products
`

func scanProduct(s rowScanner, p *models.Product) error {
	return s.Scan(
		&p.ID,
		&p.Name,
		&p.Description,
		&p.Price,
		&p.Stock,
		&p.Status,
		&p.Image,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
}

func (c *ProductController) Create(w http.ResponseWriter, r *http.Request) {
	if middleware.Type(r) != config.TypeAdmin {
		utils.Error(w, http.StatusForbidden, "admin access required")
		return
	}

	var q models.ProductCreateRequest

	if !decodeJSON(w, r, &q) {
		return
	}

	q.Name = strings.TrimSpace(q.Name)

	if q.Name == "" {
		utils.Error(w, http.StatusBadRequest, "name is required")
		return
	}

	if q.Status == 0 {
		q.Status = config.StatusActive
	}

	now := time.Now().Unix()

	result, err := c.DB.ExecContext(
		r.Context(),
		`INSERT INTO products
			(name, description, price, stock, status, image, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		q.Name,
		q.Description,
		q.Price,
		q.Stock,
		q.Status,
		q.Image,
		now,
		now,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "product create failed")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to get product id")
		return
	}

	var p models.Product

	err = scanProduct(
		c.DB.QueryRowContext(
			r.Context(),
			productSelect+` WHERE id=?`,
			id,
		),
		&p,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "product created but could not be loaded")
		return
	}

	utils.Success(w, http.StatusCreated, "product created successfully", p)
}

func (c *ProductController) GetAll(w http.ResponseWriter, r *http.Request) {
	params := utils.GetQueryParams(r, c.Cfg.PaginationLimit)
	filter := utils.NewQueryBuilder()

	if params.Search != "" {
		search := "%" + params.Search + "%"

		filter.Add(
			"(name LIKE ? OR description LIKE ?)",
			search,
			search,
		)
	}

	if status := strings.TrimSpace(
		r.URL.Query().Get("status"),
	); status != "" {
		filter.Add("status = ?", status)
	}

	if minPrice := strings.TrimSpace(
		r.URL.Query().Get("min_price"),
	); minPrice != "" {
		filter.Add("price >= ?", minPrice)
	}

	if maxPrice := strings.TrimSpace(
		r.URL.Query().Get("max_price"),
	); maxPrice != "" {
		filter.Add("price <= ?", maxPrice)
	}

	countQuery := `SELECT COUNT(*) FROM products` + filter.Where()

	var total int

	err := c.DB.QueryRowContext(
		r.Context(),
		countQuery,
		filter.Args...,
	).Scan(&total)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to count products")
		return
	}

	allowedSorts := map[string]string{
		"id":         "id",
		"name":       "name",
		"price":      "price",
		"stock":      "stock",
		"created_at": "created_at",
		"updated_at": "updated_at",
	}

	query := productSelect + filter.Where()

	query += utils.GetOrder(
		params.Sort,
		params.Order,
		allowedSorts,
		"id",
	)

	query += " LIMIT ? OFFSET ?"

	args := append(
		filter.Args,
		params.Limit,
		params.Offset,
	)

	rows, err := c.DB.QueryContext(
		r.Context(),
		query,
		args...,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to fetch products")
		return
	}

	defer rows.Close()

	products := make([]models.Product, 0)

	for rows.Next() {

		var p models.Product

		if err := scanProduct(rows, &p); err != nil {
			utils.Error(w, http.StatusInternalServerError, "failed to read products")
			return
		}

		products = append(products, p)
	}

	if err := rows.Err(); err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to read products")
		return
	}

	pagination := utils.CalculatePagination(
		params.Page,
		params.Limit,
		total,
	)

	utils.Success(w, http.StatusOK, "products fetched successfully",
		map[string]interface{}{
			"products":   products,
			"pagination": pagination,
		},
	)
}

func (c *ProductController) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid product id")
		return
	}

	var p models.Product

	err = scanProduct(
		c.DB.QueryRowContext(
			r.Context(),
			productSelect+` WHERE id=?`,
			id,
		),
		&p,
	)

	if err != nil {

		if err == sql.ErrNoRows {
			utils.Error(w, http.StatusNotFound, "product not found")
			return
		}

		utils.Error(w, http.StatusInternalServerError, "failed to fetch product")
		return
	}

	utils.Success(w, http.StatusOK, "product fetched successfully", p)
}

func (c *ProductController) Update(w http.ResponseWriter, r *http.Request) {
	if middleware.Type(r) != config.TypeAdmin {
		utils.Error(w, http.StatusForbidden, "admin access required")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid product id")
		return
	}

	var q models.ProductUpdateRequest

	if !decodeJSON(w, r, &q) {
		return
	}

	fields := make([]string, 0, 6)
	args := make([]any, 0, 8)

	if q.Name != nil {
		name := strings.TrimSpace(*q.Name)

		if name == "" {
			utils.Error(w, http.StatusBadRequest, "name cannot be empty")
			return
		}

		fields = append(fields, "name=?")
		args = append(args, name)
	}

	if q.Description != nil {
		fields = append(fields, "description=?")
		args = append(args, *q.Description)
	}

	if q.Price != nil {
		fields = append(fields, "price=?")
		args = append(args, *q.Price)
	}

	if q.Stock != nil {
		fields = append(fields, "stock=?")
		args = append(args, *q.Stock)
	}

	if q.Image != nil {
		fields = append(fields, "image=?")
		args = append(args, *q.Image)
	}

	if len(fields) == 0 {
		utils.Error(w, http.StatusBadRequest, "nothing to update")
		return
	}

	fields = append(fields, "updated_at=?")
	args = append(args, time.Now().Unix())
	args = append(args, id)

	query := `
		UPDATE products
		SET ` + strings.Join(fields, ", ") + `
		WHERE id=?
	`

	result, err := c.DB.ExecContext(r.Context(), query, args...,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "product update failed")
		return
	}

	affected, err := result.RowsAffected()

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to check product update")
		return
	}

	if affected == 0 {
		utils.Error(w, http.StatusNotFound, "product not found")
		return
	}

	c.GetByID(w, r)
}

func (c *ProductController) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	if middleware.Type(r) != config.TypeAdmin {
		utils.Error(w, http.StatusForbidden, "admin access required")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid product id")
		return
	}

	var q models.ProductStatusRequest
	if !decodeJSON(w, r, &q) {
		return
	}

	if q.Status != config.StatusActive &&
		q.Status != config.StatusInactive &&
		q.Status != config.StatusBan {

		utils.Error(w, http.StatusBadRequest, "invalid status")
		return
	}

	result, err := c.DB.ExecContext(
		r.Context(),
		`UPDATE products
		 SET status=?, updated_at=?
		 WHERE id=?`,
		q.Status,
		time.Now().Unix(),
		id,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "product status update failed")
		return
	}

	affected, err := result.RowsAffected()

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to check product status update")
		return
	}

	if affected == 0 {
		utils.Error(w, http.StatusNotFound, "product not found")
		return
	}

	c.GetByID(w, r)
}

func (c *ProductController) Delete(w http.ResponseWriter, r *http.Request) {
	if middleware.Type(r) != config.TypeAdmin {
		utils.Error(w, http.StatusForbidden, "admin access required")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid product id")
		return
	}

	result, err := c.DB.ExecContext(
		r.Context(),
		`DELETE FROM products WHERE id=?`,
		id,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "product delete failed")
		return
	}

	affected, err := result.RowsAffected()

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to check product delete")
		return
	}

	if affected == 0 {
		utils.Error(w, http.StatusNotFound, "product not found")
		return
	}

	utils.Success(w, http.StatusOK, "product deleted successfully", nil)
}
