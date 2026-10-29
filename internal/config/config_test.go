package config

import "testing"

func TestValidateRejectsPublicAdmin(t *testing.T) {
	var c Config
	c.Defaults()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Control.AdminListen = ":8081"
	if c.Validate() == nil {
		t.Fatal("public control admin accepted")
	}
	c.Control.AdminListen = "127.0.0.1:8081"
	c.Node.AdminListen = "0.0.0.0:9100"
	if c.Validate() == nil {
		t.Fatal("public node admin accepted")
	}
}
