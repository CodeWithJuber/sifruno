package sitebackups

import (
	"errors"
	"strings"

	"sifruno/internal/hostaccounts"
)

// registryError is a failure to read the site's databases from dbhost's
// registry.
type registryError struct{ err error }

func (e *registryError) Error() string { return "database registry: " + e.err.Error() }
func (e *registryError) Unwrap() error { return e.err }

// Explain turns a failed backup, restore, drill or prune into a message that
// says what happened, why and what to do next, with the step and the
// broker's own words for "Technical details". kind is backup, restore,
// drill or prune.
func Explain(err error, kind string) (message, step, detail string) {
	var failed *hostaccounts.BackupError
	var registry *registryError
	switch {
	case errors.As(err, &failed):
		return stepMessage(failed.Step, failed.Detail, kind), failed.Step, failed.Detail
	case errors.As(err, &registry):
		return "The panel could not read this site's databases from its registry, so nothing was backed up. Check that MariaDB is running, then try again.", "registry", technical(registry.err.Error())
	case errors.Is(err, hostaccounts.ErrConflict):
		return "The site was busy with another change, or its folders were changed, so the account service refused and nothing changed. Try again in a few minutes.", "", "account service: " + err.Error()
	case errors.Is(err, hostaccounts.ErrInvalid):
		return "The account service refused the request as invalid, so nothing changed. Reload the page and try again.", "", "account service: " + err.Error()
	case errors.Is(err, hostaccounts.ErrNotFound):
		return "The site's hosting account was not found, so nothing changed. It may have been deleted.", "", "account service: " + err.Error()
	case errors.Is(err, hostaccounts.ErrRecovery):
		return "The account service has an unfinished change and refuses every other change until someone has checked it. Nothing changed.", "", "account service: " + err.Error()
	case errors.Is(err, hostaccounts.ErrUnavailable):
		return "The account service could not run the backup tools, so nothing changed. restic, ssh or the MariaDB tools may be missing, or restic is not the version the panel was built for. Run the installer again, then try again.", "", "account service: " + err.Error()
	default:
		return "The account service did not answer, so the panel cannot tell how this ended. Reload the page to see the backups as they are now.", "", technical(err.Error())
	}
}

func stepMessage(step, detail, kind string) string {
	done := map[string]string{"backup": "nothing was backed up", "restore": "the site was not changed", "drill": "the drill could not finish", "prune": "no old backups were removed", "list": "the backups cannot be listed"}[kind]
	if done == "" {
		done = "nothing changed"
	}
	human := strings.HasPrefix(detail, "The ") || strings.HasPrefix(detail, "That ") || strings.HasPrefix(detail, "This ")
	switch step {
	case "target":
		return "Backup storage is not set up, so " + done + ". Set it up on the Backup storage page, then try again."
	case "connect":
		return "The panel could not reach the backup storage server, so " + done + ". Check its address, user and host key, and that this server's backup key is installed for that user, then try again."
	case "password":
		return "That storage folder already holds backups made with another password, so this server cannot use it. Choose an empty folder, or the folder this server's own backups are in."
	case "repository":
		return "The storage server answered, but the backup repository there could not be opened, so " + done + ". Open Technical details for restic's message."
	case "database":
		if human {
			return detail + " Nothing was backed up."
		}
		return "MariaDB did not answer the check of this site's databases, so nothing was backed up. Check that MariaDB is running, then try again."
	case "dump":
		return "MariaDB could not dump this site's database, so nothing was backed up. Check that MariaDB is running, then try again."
	case "backup":
		return "restic could not finish the backup, so no new backup was made. The storage server may be full or out of reach. Open Technical details for restic's message."
	case "snapshot":
		if human {
			return detail
		}
		return "The list of backups could not be read from the storage server, so " + done + ". Try again; if it keeps failing, check the storage server."
	case "restore":
		if kind == "drill" {
			return "The drill could not restore the latest backup. The backup may be damaged or out of reach. Make a new backup and run the drill again; open Technical details for restic's message."
		}
		return "restic could not restore the backup into the staging folder, so the site was not changed. Open Technical details for restic's message, then try again."
	case "copy":
		return "The backup was restored to a staging folder, but copying the files into the site stopped partway, so some files may already be restored. Open Technical details, fix the cause, then restore the files again."
	case "import":
		return "The database could not be loaded from the backup, so it may be partly restored. Open Technical details, fix the cause, then restore the database again."
	case "compare":
		return "The drill restored the latest backup, but it did not match the backup's own file list, so the backup may be damaged. Make a new backup now and run the drill again."
	case "check":
		return "restic found a problem in the stored backup data. Make a new backup and run the drill again; if it fails again, check the storage server's disk."
	case "prune":
		return "restic could not remove old backups. New backups still run. Open Technical details for restic's message."
	}
	return "A backup step failed, so " + done + ". Open Technical details for what the account service said."
}

// technical keeps an error's text short and printable for "Technical
// details".
func technical(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < 512; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b = append(b, c)
		}
	}
	return string(b)
}
