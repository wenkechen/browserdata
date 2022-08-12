//go:build windows

package chromium

import (
	"encoding/base64"
	"errors"
	"os"

	"github.com/tidwall/gjson"

	"github.com/wenkechen/browserdata/decrypter"
	"github.com/wenkechen/browserdata/item"
	"github.com/wenkechen/browserdata/log"
	"github.com/wenkechen/browserdata/utils/fileutil"
)

var errDecodeMasterKeyFailed = errors.New("decode master key failed")

func (c *chromium) GetMasterKey() ([]byte, error) {
	keyFile, err := fileutil.ReadFile(item.TempChromiumKey)
	if err != nil {
		return nil, err
	}
	defer os.Remove(keyFile)
	encryptedKey := gjson.Get(keyFile, "os_crypt.encrypted_key")
	if encryptedKey.Exists() {
		pureKey, err := base64.StdEncoding.DecodeString(encryptedKey.String())
		if err != nil {
			return nil, errDecodeMasterKeyFailed
		}
		c.masterKey, err = decrypter.DPApi(pureKey[5:])
		log.Infof("%s initialized master key success", c.name)
		return c.masterKey, err
	}
	return nil, nil
}
