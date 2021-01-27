package outline

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

var unsafeClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// {
// "id":"3",
// "name":"",
// "password":"5PgTilMvdrhK",
// "port":61081,
// "method":"chacha20-ietf-poly1305",
// "accessUrl":"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo1UGdUaWxNdmRyaEs=@18.182.68.185:61081/?outline=1"
// }
type OutlineUser struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Password         string `json:"password"`
	Port             int    `json:"port"`
	Method           string `json:"method"`
	AccessURL        string `json:"accessUrl"`
	DataLimit        uint64 `json:"dataLimit,omitempty"`
	TransferredBytes uint64 `json:"byteNum,omitempty"`
}

// Outline apiUrl
// https://127.0.0.1:56298/QQR9pcgCRP_g5OLX3n-w-g
type OutlineServer struct {
	URL string `json:"url,omitempty"`

	Name                 string `json:"name"`
	ServerID             string `json:"serverId"`
	MetricsEnabled       bool   `json:"metricsEnabled"`
	CreatedTimestampMs   uint64 `json:"createdTimestampMs"`
	PortForNewAccessKeys int    `json:"portForNewAccessKeys"`

	Users map[string]*OutlineUser `json:"_,omitempty"`
}

func NewOutlineServer(url string) (*OutlineServer, error) {
	s := &OutlineServer{URL: url}
	if err := s.GetServerInfo(); err != nil {
		return nil, err
	}
	if err := s.GetAllUser(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *OutlineServer) GetServerInfo() error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/server", s.URL), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		return &CodeError{Code: r.StatusCode}
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(b, s); err != nil {
		return err
	}

	return nil
}

func (s *OutlineServer) GetUsage() (map[string]uint64, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/metrics/transfer", s.URL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		return nil, &CodeError{Code: r.StatusCode}
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	type BytesTransferred struct {
		ByUserID map[string]uint64 `json:"bytesTransferredByUserId"`
	}

	used := BytesTransferred{ByUserID: make(map[string]uint64)}
	if err := json.Unmarshal(b, &used); err != nil {
		return nil, err
	}

	return used.ByUserID, nil
}

func (s *OutlineServer) GetAllUser() error {
	s.Users = make(map[string]*OutlineUser)

	usage, err := s.GetUsage()
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/access-keys", s.URL), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		return &CodeError{Code: r.StatusCode}
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	type Users struct {
		AccessKeys []*OutlineUser `json:"accessKeys"`
	}

	users := Users{}
	if err := json.Unmarshal(b, &users); err != nil {
		return err
	}
	for _, user := range users.AccessKeys {
		user.TransferredBytes = usage[user.ID]
		s.Users[user.ID] = user
	}

	return nil
}

func (s *OutlineServer) AddUser() (*OutlineUser, error) {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/access-keys", s.URL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusCreated {
		return nil, &CodeError{Code: r.StatusCode}
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	user := &OutlineUser{}
	if err := json.Unmarshal(b, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *OutlineServer) DeleteUser(id string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/access-keys/%s", s.URL, id), nil)
	if err != nil {
		return err
	}

	r, err := unsafeClient.Do(req)
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusNoContent {
		return &CodeError{Code: r.StatusCode}
	}
	defer r.Body.Close()

	return nil
}

func (s *OutlineServer) SetDataLimit(id string, n uint64) error {
	type Limit struct {
		Bytes uint64 `json:"bytes"`
	}
	type Limitor struct {
		Limit `json:"limit"`
	}
	limit := Limitor{Limit: Limit{Bytes: n}}
	b, err := json.Marshal(limit)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/access-keys/%s/data-limit", s.URL, id), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusNoContent {
		switch r.StatusCode {
		case http.StatusBadRequest:
			return errors.New("invalid data limit")
		case http.StatusNotFound:
			return errors.New("access key inexistent")
		}
		return &CodeError{Code: r.StatusCode}
	}
	defer r.Body.Close()
	return nil
}

func (s *OutlineServer) AddUserWithDataLimit(n uint64) error {
	user, err := s.AddUser()
	if err != nil {
		return err
	}
	return s.SetDataLimit(user.ID, n)
}

type CodeError struct {
	Code int
}

func (err *CodeError) Error() string {
	return fmt.Sprintf("status code (%v: %s) error", err.Code, http.StatusText(err.Code))
}
