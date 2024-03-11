package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// rsa私钥
//
//go:embed rsa_key
var rsa_key []byte

// rsa公钥
//
//go:embed rsa_pub
var rsa_pub []byte

// 随机字符
var chars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

type jwtClaims struct {
	UserID     int    `json:"user_id"`
	Username   string `json:"username"`
	GrantScope string `json:"grant_scope"`
	gjwt.RegisteredClaims
}

// 生成指定长度的随机字符串
func generateRandomString(str_len int) string {
	randBytes := make([]rune, str_len)
	for i := range randBytes {
		randBytes[i] = chars[rand.Intn(len(chars))]
	}
	return string(randBytes)
}

func parsePriKeyBytes(buf []byte) (*rsa.PrivateKey, error) {
	p := &pem.Block{}
	if p, _ = pem.Decode(buf); p == nil {
		return nil, errors.New("parse key error")
	}
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

func parsePubKeyBytes(pub_key []byte) (*rsa.PublicKey, error) {
	var block *pem.Block
	var pubRet *rsa.PublicKey
	var err error
	if block, _ = pem.Decode(pub_key); block == nil {
		return nil, errors.New("block nil")
	}
	if pubRet, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
		return nil, errors.New("x509.ParsePKCS1PublicKey error")
	}

	return pubRet, nil
}

func GenerateToken() (string, error) {
	claim := jwtClaims{
		UserID:     000001,
		Username:   "Tom",
		GrantScope: "read_user_info",
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    "Auth_Server",                                    // 签发者
			Subject:   "Tom",                                            // 签发对象
			Audience:  gjwt.ClaimStrings{"Android_APP", "IOS_APP"},      //签发受众
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Hour)),   //过期时间
			NotBefore: gjwt.NewNumericDate(time.Now().Add(time.Second)), //最早使用时间
			IssuedAt:  gjwt.NewNumericDate(time.Now()),                  //签发时间
			ID:        generateRandomString(10),                         // jwt ID, 类似于盐值
		},
	}
	rsa_pri_key, _ := parsePriKeyBytes(rsa_key)
	token, err := gjwt.NewWithClaims(gjwt.SigningMethodRS256, claim).SignedString(rsa_pri_key)
	return token, err
}

func ParseToken(token_string string) (*jwtClaims, error) {
	var err error
	var token *gjwt.Token
	var claims *jwtClaims
	var ok bool
	if token, err = gjwt.ParseWithClaims(token_string, &jwtClaims{}, func(token *gjwt.Token) (interface{}, error) {
		pub, err := parsePubKeyBytes(rsa_pub)
		if err != nil {
			fmt.Println("err = ", err)
			return nil, err
		}
		return pub, nil
	}); err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("claim invalid")
	}

	if claims, ok = token.Claims.(*jwtClaims); !ok {
		return nil, errors.New("invalid claim type")
	}

	return claims, nil
}
