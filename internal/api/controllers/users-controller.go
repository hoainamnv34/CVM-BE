package controllers

import (
	"net/http"

	models "vulnerability-management/internal/pkg/models/users"
	persistence "vulnerability-management/internal/pkg/persistence"
	helpers "vulnerability-management/pkg/helpers"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetUserByID godoc
// @Summary     Get user by ID
// @Description Get user by ID
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/users/{id} [get]
// @Security    Authorization Token
// @Tags        User
func GetUserByID(c *gin.Context) {
	id := c.Param("id")

	user, err := persistence.UserRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "User is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    user,
	})
}

// GetUsers godoc
// @Summary     Get users by query
// @Description Get users by query
// @Produce     json
// @Param       name            query    string  false "name"
// @Param       pipeline_run_id query    integer false "pipeline_run_id"
// @Param       tool_type_id    query    integer false "tool_type_id"
// @Param       page            query    integer false "page"
// @Param       size            query    integer false "size"
// @Success     200             {object} http_res.HTTPResponse
// @Router      /api/users [get]
// @Security    Authorization Token
// @Tags        User
func GetUsers(c *gin.Context) {
	query := models.User{}

	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})

		return
	}

	where := map[string]interface{}{}

	if query.UserName != "" {
		where["username"] = query.UserName
	}

	if query.Password != "" {
		where["password"] = query.Password
	}

	if query.FullName != "" {
		where["full_name"] = query.FullName
	}

	if query.Email != "" {
		where["email"] = query.Email
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	users, count, err := persistence.UserRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Users not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      users,
		DataCount: count,
	})
}

// CreateUser godoc
// @Summary     Create user
// @Description Create user
// @Accept      json
// @Produce     json
// @Param       body body     models.User true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/users [post]
// @Tags        User
func CreateUser(c *gin.Context) {
	body := models.User{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})

		return
	}

	user := models.User{
		UserName: body.UserName,
		Password: body.Password,
		FullName: body.FullName,
		Email:    body.Email,
	}

	res, err := persistence.UserRepo.Add(&user)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})

		return
	}

	c.JSON(http.StatusCreated, http_res.HTTPResponse{
		Code:    http.StatusCreated,
		Message: "Success",
		Data:    res,
	})
}

// UpdateUser godoc
// @Summary     Update user by ID
// @Description Update user by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer     true "id" min(1)
// @Param       body body     models.User true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/users/{id} [put]
// @Tags        User
func UpdateUser(c *gin.Context) {
	body := models.User{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})

		return
	}

	id := c.Param("id")

	user, err := persistence.UserRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "User is not found",
		})

		return
	}

	if body.UserName != "" {
		user.UserName = body.UserName
	}

	if body.Password != "" {
		user.Password = body.Password
	}

	if body.FullName != "" {
		user.FullName = body.FullName
	}

	if body.Email != "" {
		user.Email = body.Email
	}

	err = persistence.UserRepo.Update(user)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "User is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// DeleteUser godoc
// @Summary     Delete user by ID
// @Description Delete user by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/users/{id} [delete]
// @Tags        User
func DeleteUser(c *gin.Context) {
	id := c.Param("id")

	user, err := persistence.UserRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "User is not found",
		})

		return
	}

	err = persistence.UserRepo.Delete(user)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "User is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
