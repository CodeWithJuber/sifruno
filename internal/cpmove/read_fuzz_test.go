package cpmove

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// FuzzRead feeds Read arbitrary bytes. It must never panic, never hand the
// sink a name outside the stage (memSink fails the test), and whatever it
// accepts must be a website model that passes Check and holds no password
// hash or key.
func FuzzRead(f *testing.F) {
	f.Add(shopArchive(f))
	f.Add(tarOf(f, file("cpmove-shop/cp/shop", "DNS=example.com\n"), file("cpmove-shop/userdata/main", "main_domain: example.com\nparked_domains:\n  - example.net\n"),
		file("cpmove-shop/mysql.sql", "GRANT USAGE ON *.* TO 'shop_a'@'localhost' IDENTIFIED BY PASSWORD '"+testHash+"';\nGRANT SELECT ON `shop\\_a`.* TO 'shop_a'@'localhost';\n"),
		file("cpmove-shop/mysql/shop_a.sql", "SELECT 1;\n"), link("cpmove-shop/homedir/x", "../../y")))
	f.Add([]byte{0x1f, 0x8b})
	limits := DefaultLimits()
	limits.MaxArchiveBytes, limits.MaxExpandedBytes, limits.MaxFileBytes, limits.MaxEntries = 1<<20, 4<<20, 1<<20, 200
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		a, err := Read(ctx, bytes.NewReader(data), limits, newMemSink(t))
		if err != nil {
			return
		}
		if err := a.Site.Check(); err != nil {
			t.Fatalf("Read accepted a model Check refuses: %v", err)
		}
		model := strings.Join(append(a.Site.Aliases, a.Site.Domain, a.Site.PHP.Source), " ")
		for _, item := range a.Site.NotCarried {
			model += " " + item.Text + " " + item.Where
		}
		for _, u := range a.Users {
			if u.Hash != "" && strings.Contains(model, u.Hash) {
				t.Fatal("the model quotes a password hash")
			}
		}
	})
}
