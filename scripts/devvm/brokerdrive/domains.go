package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"sifruno/internal/acme"
	"sifruno/internal/hostaccounts"
)

// readSiteDomains reads a domains file: one JSON object with exactly the
// keys aliases and redirects.
func readSiteDomains(path string) (hostaccounts.SiteDomains, error) {
	if path == "" {
		return hostaccounts.SiteDomains{}, errors.New("no --input-file given")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return hostaccounts.SiteDomains{}, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var set hostaccounts.SiteDomains
	if err := d.Decode(&set); err != nil {
		return hostaccounts.SiteDomains{}, err
	}
	if set.Aliases == nil || set.Redirects == nil {
		return hostaccounts.SiteDomains{}, errors.New("the file needs both aliases and redirects, each possibly []")
	}
	return set, nil
}

// secured is what secure prints: the aliases left out because they did not
// reach this server, and the account as the broker lists it afterwards.
type secured struct {
	Waiting []string             `json:"waiting"`
	Account hostaccounts.Account `json:"account"`
}

// secure brings one account's certificate up to date the way the panel does
// after a domain change: acme.Manager.Refresh probes each alias, asks the
// ACME server for the site's domain and the aliases that reach this server,
// and installs the result through the broker's SetCertificate.
func secure(ctx context.Context, service hostaccounts.Service, certs hostaccounts.CertificateService, id string, cfg acme.Config, actor string) (secured, error) {
	account, err := listed(ctx, service, id)
	if err != nil {
		return secured{}, err
	}
	m, err := acme.New(cfg, installer{certs: certs, actor: actor}, noSites{})
	if err != nil {
		return secured{}, err
	}
	site := acme.Site{AccountID: account.ID, Domain: account.Domain, Revision: account.Revision, Active: account.State == "active"}
	if account.SiteDomains != nil {
		site.Aliases = slices.Clone(account.SiteDomains.Aliases)
	}
	if account.Certificate.NotAfter > 0 {
		site.NotAfter = time.Unix(account.Certificate.NotAfter, 0)
	}
	if account.Certificate.Names != "" {
		site.Covered = strings.Split(account.Certificate.Names, ",")
	}
	if err := m.Refresh(ctx, site); err != nil {
		return secured{}, err
	}
	account, err = listed(ctx, service, id)
	if err != nil {
		return secured{}, err
	}
	waiting := m.Waiting(id)
	if waiting == nil {
		waiting = []string{}
	}
	return secured{Waiting: waiting, Account: account}, nil
}

func listed(ctx context.Context, service hostaccounts.Service, id string) (hostaccounts.Account, error) {
	accounts, err := service.List(ctx)
	if err != nil {
		return hostaccounts.Account{}, err
	}
	for _, a := range accounts {
		if a.ID == id {
			return a, nil
		}
	}
	return hostaccounts.Account{}, hostaccounts.ErrNotFound
}

// installer is the panel's broker installer (cmd/sifruno), for this tool.
type installer struct {
	certs hostaccounts.CertificateService
	actor string
}

func (i installer) Install(ctx context.Context, accountID string, revision uint64, certPEM, keyPEM []byte) (uint64, time.Time, error) {
	res, err := i.certs.SetCertificate(ctx, accountID, hostaccounts.CertificateInput{ExpectedRevision: revision, CertPEM: string(certPEM), KeyPEM: string(keyPEM), Reason: "Dev VM proof certificate"}, i.actor)
	if err != nil {
		return 0, time.Time{}, err
	}
	return res.Account.Revision, time.Unix(res.Certificate.NotAfter, 0), nil
}

// noSites: this tool runs no renewal loop.
type noSites struct{}

func (noSites) Sites(context.Context) ([]acme.Site, error) { return nil, nil }
