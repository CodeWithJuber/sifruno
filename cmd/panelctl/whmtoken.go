package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"sifruno/internal/whmapi"
)

// runWHMToken issues, lists and revokes WHM API tokens in the panel's
// root-only store. The plaintext token prints exactly once at creation.
func runWHMToken(args []string, state string, out, errs io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: whm-token create --user USER --name NAME | list | revoke --name NAME")
	}
	storePath := filepath.Join(state, "whmapi-tokens.json")
	store, err := whmapi.OpenTokenStore(storePath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "create":
		f := flag.NewFlagSet("whm-token create", flag.ContinueOnError)
		f.SetOutput(errs)
		user := f.String("user", "root", "Owning WHM user")
		name := f.String("name", "", "Token name (a-z A-Z 0-9 _ -, max 50)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			return errors.New("--name is required")
		}
		token, info, err := store.Create(*user, *name)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "name=%s user=%s create_time=%d\ntoken=%s\n", info.Name, info.User, info.CreateTime, token)
		fmt.Fprintln(out, "Store this token now; it is never shown again.")
		return nil
	case "list":
		infos := store.List()
		if len(infos) == 0 {
			fmt.Fprintln(out, "no tokens issued")
			return nil
		}
		for _, info := range infos {
			fmt.Fprintf(out, "%s\tuser=%s\tcreated=%d\n", info.Name, info.User, info.CreateTime)
		}
		return nil
	case "revoke":
		f := flag.NewFlagSet("whm-token revoke", flag.ContinueOnError)
		f.SetOutput(errs)
		name := f.String("name", "", "Token name")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			return errors.New("--name is required")
		}
		return store.Revoke(*name)
	default:
		return fmt.Errorf("unknown whm-token action %q", args[0])
	}
}
