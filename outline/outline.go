package outline

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
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
	TransferredBytes uint64 `json:"byteNum,omitempty"`
}

// Outline apiUrl
// https://127.0.0.1:56298/QQR9pcgCRP_g5OLX3n-w-g
type OutlineServer struct {
	URL string `json:"_,omitempty"`

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
	req, err := http.NewRequest(http.MethodGet, s.URL+"/server", nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		return errors.New("status code error, code: " + strconv.Itoa(r.StatusCode))
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if err := json.Unmarshal(b, s); err != nil {
		return err
	}

	return nil
}

func (s *OutlineServer) GetUsage() (map[string]uint64, error) {
	req, err := http.NewRequest(http.MethodGet, s.URL+"/metrics/transfer", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		return nil, errors.New("status code error, code: " + strconv.Itoa(r.StatusCode))
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

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

	req, err := http.NewRequest(http.MethodGet, s.URL+"/access-keys", nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	r, err := unsafeClient.Do(req)
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		return errors.New("status code error, code: " + strconv.Itoa(r.StatusCode))
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

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
