package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type SMSResponse struct {
	Error int    `json:"error"`
	Msg   string `json:"msg"`
	Data  struct {
		RequestID int64 `json:"request_id"`
	} `json:"data"`
}

func SendSMS(apiURL string, apiKey string, phone string, message string) (int64, error) {
	phone = strings.TrimSpace(phone)

	if strings.HasPrefix(phone, "01") {
		phone = "88" + phone
	}

	params := url.Values{}
	params.Set("api_key", apiKey)
	params.Set("msg", message)
	params.Set("to", phone)

	requestURL := apiURL + "?" + params.Encode()

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	var result SMSResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	if result.Error != 0 {
		return 0, fmt.Errorf(
			"sms.bd error %d: %s",
			result.Error,
			result.Msg,
		)
	}

	return result.Data.RequestID, nil
}
