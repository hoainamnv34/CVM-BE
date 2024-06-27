package helpers

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

const MAX_LIMIT int = math.MaxInt
const DEFAULT_LIMIT int = 100
const MIN_LIMIT int = 0
const MIN_PAGE int = 1

// Returns the offset and limit for pagination
func GetPagination(page string, size string) (int, int) {
	pageInt, err := strconv.Atoi(page)
	if err != nil || pageInt < MIN_PAGE {
		pageInt = MIN_PAGE
	}

	limitInt, err := strconv.Atoi(size)
	if err != nil || limitInt < MIN_LIMIT {
		limitInt = DEFAULT_LIMIT
	} else if limitInt == MIN_LIMIT {
		limitInt = MAX_LIMIT
	}

	offset := (pageInt - 1) * limitInt

	return offset, limitInt
}

// SortOrder returns the string for sorting and orderin data
func SortOrder(table, sort, order string) string {
	return table + "." + ToSnakeCase(sort) + " " + ToSnakeCase(order)
}

// ToSnakeCase changes string to database table
func ToSnakeCase(str string) string {
	var matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")

	return strings.ToLower(snake)
}
