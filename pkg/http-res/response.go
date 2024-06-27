package http_res

type HTTPResponse struct {
	Code      int         `json:"code,omitempty"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	DataCount int         `json:"data_count,omitempty"`
}
