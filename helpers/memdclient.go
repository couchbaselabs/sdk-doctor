package helpers

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/couchbaselabs/sdk-doctor/memd"
)

// MemdClient provides a memcached client
type MemdClient struct {
	conn memd.ReadWriteCloser
}

// Dial will dial a particular host and return a MemdClient
func Dial(host string, port int, bucket, user, pass string, tlsConfig *tls.Config) (*MemdClient, error) {
	if user == "" {
		user = bucket
	}

	address := fmt.Sprintf("%s:%d", host, port)

	deadline := time.Now().Add(time.Millisecond * 2000)

	var srvTLSConfig *tls.Config
	if tlsConfig != nil {
		srvTLSConfig = tlsConfig.Clone()
		srvTLSConfig.ServerName = host
	}

	conn, err := memd.DialMemdConn(address, srvTLSConfig, deadline)
	if err != nil {
		return nil, err
	}

	var client MemdClient
	client.conn = conn

	// do not use SASL for client authentication
	if user != "" && pass != "" {
		err = client.auth(user, pass)
		if err != nil {
			client.Close()
			return nil, err
		}
	}

	if bucket != user || 
	   (tlsConfig != nil && len(tlsConfig.Certificates) > 0) {
		err = client.selectBucket(bucket)
		if err != nil {
			client.Close()
			return nil, err
		}
	}

	return &client, nil
}

// Close closes a connection
func (client *MemdClient) Close() {
	client.conn.Close()
}

func (client *MemdClient) auth(user, pass string) error {
	var resp memd.Response

	err := client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdSASLListMechs,
	})
	if err != nil {
		return err
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return err
	}

	if resp.Status != 0 {
		return errors.New("unexpected SASLListMechs status")
	}

	mechs := strings.Split(string(resp.Value), " ")

	foundPlainMech := false
	for _, mech := range mechs {
		if mech == "PLAIN" {
			foundPlainMech = true
		}
	}

	if !foundPlainMech {
		return errors.New("server does not support PLAIN SASL")
	}

	// Build PLAIN auth data
	userBuf := []byte(user)
	passBuf := []byte(pass)
	authData := make([]byte, 1+len(userBuf)+1+len(passBuf))
	authData[0] = 0
	copy(authData[1:], userBuf)
	authData[1+len(userBuf)] = 0
	copy(authData[1+len(userBuf)+1:], passBuf)

	err = client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdSASLAuth,
		Key:    []byte("PLAIN"),
		Value:  authData,
	})
	if err != nil {
		return err
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return err
	}

	if resp.Status != 0 {
		if resp.Status == memd.StatusAuthError {
			return errors.New("invalid bucket name/password")
		}

		return fmt.Errorf("SASL auth failed for user `%s` (status: %d)", user, resp.Status)
	}

	return nil
}

func (client *MemdClient) selectBucket(bucket string) error {
	var resp memd.Response

	err := client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdSelectBucket,
		Key:    []byte(bucket),
	})
	if err != nil {
		return err
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return err
	}

	if resp.Status != 0 {
		return fmt.Errorf("failed to select bucket `%s` (status: %d)", bucket, resp.Status)
	}

	return nil
}

// GetConfig will fetch a config via CCCP
func (client *MemdClient) GetConfig() ([]byte, error) {
	var resp memd.Response

	err := client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdGetClusterConfig,
	})
	if err != nil {
		return nil, err
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return nil, err
	}

	if resp.Status != memd.StatusSuccess {
		return nil, fmt.Errorf("failed to get config (status: %d)", resp.Status)
	}

	return resp.Value, nil
}

// Ping will send a ping and wait for a response
func (client *MemdClient) Ping() error {
	var resp memd.Response

	client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdNop,
	})

	err := client.conn.ReadPacket(&resp)
	if err != nil {
		return err
	}

	return nil
}
