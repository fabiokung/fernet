package fernet

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

var jsonVerifyTokens = []*test{
	{
		secret: "JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=",
		src:    []byte(`{"email":"harold@heroku.com","id":"123","arbitrary":"data","issued_at":"2013-01-01T16:28:21-08:00"}`),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("GuAoWrTdBSD3tOAqsTwsqScn7Bx5qi-Yf4R2r1tZ-1MZfU3WxQheTzjwueWMkLCkMbndpcaCULDTmqK4TUgvSa9og_8qSSlyCan3gZrThB1OCJnFxFyf6AgZSic4nGLASedMY8lxTdaOrfe3gdhZGg==|ALJUvh2vqAAOePxO2DN3HA==|2b0eae68d66718f09c62c5fe6803ed25e59a07d7c3080c3e7599337ee17c0d9f"),
		desc:   "json style",
	},
}

var hexKeyVerifyTokens = []*test{
	{
		secret: "c231bf0b8a18cf3235d0204a20b8d8aae8f00ee6bf0d51f5dc423f99f05301a2",
		msg:    Message{"from the ruby version"},
		now:    time.Date(2013, time.May, 21, 15, 29, 41, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    5000 * time.Hour,
		token:  []byte("UDkmjpq600iYZmPnKXXlBVCIsek-80tHS8hVB-ZFBdifxkeVDN1Fn6NCJRMVUdiaPJI8HGpEMfrOUajsr4iGYwXVW1NFCs9RJPCKmmrVMbI=|BVVtQ13Z4NbstlhvkR7BNw==|78b5bc670a4f3d0f6275873cd8f98673a464ee21b2fe8c41e215a9c7e50cc66d"),
		desc:   "from the ruby fernet",
	},
}

func TestJsonVerifyOk(t *testing.T) {
	for i, tok := range jsonVerifyTokens {
		t.Logf("test %d %s", i, tok.desc)
		k := Key(tok.secret)
		g := jsonVerify(tok.token, tok.ttl, tok.now, k)
		if !reflect.DeepEqual(g, tok.src) {
			t.Errorf("got %#v != exp %#v", string(g), string(tok.src))
		}
	}
}

func TestHexKeyVerifyOk(t *testing.T) {
	for i, tok := range hexKeyVerifyTokens {
		t.Logf("test %d %s", i, tok.desc)
		k := Key(tok.secret)
		g := jsonVerify(tok.token, tok.ttl, tok.now, k)
		var m Message
		err := json.Unmarshal(g, &m)
		if err != nil || tok.msg != m {
			t.Error(err)
			t.Errorf("got %#v != exp %#v", string(g), tok.msg)
		}
	}
}

func BenchmarkJsonVerifyOk(b *testing.B) {
	tok := jsonVerifyTokens[0]
	k := MustDecodeKey(tok.secret)
	for i := 0; i < b.N; i++ {
		jsonVerify(tok.token, tok.ttl, tok.now, k)
	}
}
