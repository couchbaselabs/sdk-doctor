package helpers

import (
	"errors"
	"fmt"
	"github.com/couchbaselabs/sdk-doctor/memd"
	"strings"
	"time"
)

type MemdClient struct {
	conn memd.MemdReadWriteCloser
}

func Dial(host string, port int, bucket, user, pass string) (*MemdClient, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	deadline := time.Now().Add(time.Millisecond * 2000)

	conn, err := memd.DialMemdConn(address, nil, deadline)
	if err != nil {
		return nil, err
	}

	var client MemdClient
	client.conn = conn

	err = client.auth(user, pass)
	if err != nil {
		client.Close()
		return nil, err
	}

	if bucket != user {
		err = client.selectBucket(bucket)
		if err != nil {
			client.Close()
			return nil, err
		}
	}

	return &client, nil
}

func (client *MemdClient) Close() {
	client.conn.Close()
}

func (client *MemdClient) auth(user, pass string) error {
	var resp memd.MemdResponse

	err := client.conn.WritePacket(&memd.MemdRequest{
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

	err = client.conn.WritePacket(&memd.MemdRequest{
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

		return errors.New(fmt.Sprintf("SASL auth failed (status: %d)", resp.Status))
	}

	return nil
}

func (client *MemdClient) selectBucket(bucket string) error {
	var resp memd.MemdResponse

	err := client.conn.WritePacket(&memd.MemdRequest{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdSelectBucket,
		Value:  []byte(bucket),
	})
	if err != nil {
		return err
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return err
	}

	if resp.Status != 0 {
		return errors.New(fmt.Sprintf("failed to select bucket (status: %d)", resp.Status))
	}

	return nil
}

func (client *MemdClient) GetConfig() ([]byte, error) {
	var resp memd.MemdResponse

	err := client.conn.WritePacket(&memd.MemdRequest{
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
		return nil, errors.New(fmt.Sprintf("failed to get config (status: %d)", resp.Status))
	}

	return resp.Value, nil
}

func (client *MemdClient) Ping() error {
	var resp memd.MemdResponse

	client.conn.WritePacket(&memd.MemdRequest{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdNop,
	})

	err := client.conn.ReadPacket(&resp)
	if err != nil {
		return err
	}

	return nil
}
