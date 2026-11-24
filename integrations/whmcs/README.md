# Sifruno module for WHMCS

A WHMCS server module (provisioning module) for Sifruno. Each WHMCS service is one WordPress website on a Sifruno panel:

| WHMCS action | What the module does on the panel |
| --- | --- |
| Test Connection | Reads the list of websites with the API token. |
| Create | Starts the New website wizard (`POST /api/v1/websites/wordpress`) for the service's domain, with the client's email, a new 32-character WordPress admin password and the product's PHP version. |
| Suspend | Reads the website for its revision, then sets it to `suspended` with `expected_revision`. Visitors get 403. |
| Unsuspend | The same with `active`. |
| Terminate | Deletes the website, its database and its hosting account, with the service's domain as `confirm_domain` and `expected_revision`. |
| Admin service page | Shows the website's state, address and PHP version, or the wizard job's progress or failure. |

It is the small Phase 1 module from the plan. Package mapping, single sign-on, usage, password change and package change come later.

The module calls the panel's API over HTTPS with an API token. It uses PHP's own curl and json extensions; there is nothing to install with Composer.

## What you need

- WHMCS 8 (7.2 or later works: the module saves its IDs as Service Properties) on PHP 8.1 or later, with curl and json.
- A Sifruno panel that serves HTTPS to the network: install it with `--panel-host NAME`, where NAME is the name WHMCS will use. It listens on port 8443. Allow the WHMCS server's address to that port in the panel server's firewall.
- An API token from the panel.

## Install

1. Copy the `modules/servers/sifruno` folder into the `modules/servers` folder of your WHMCS installation, so that WHMCS has `modules/servers/sifruno/sifruno.php`.
2. In the panel, open Security › API tokens and create a token named, for example, "WHMCS". It is shown once; copy it. Tokens last 90 days unless you choose up to 365, so note the date and replace it before then.
3. If the panel uses its own self-signed certificate (the default), copy `/var/lib/sifpanel/state/tls/panel-cert.pem` from the panel server to the WHMCS server, for example to `/etc/whmcs/sifruno-panel.pem`, readable by the user PHP runs as. The panel makes a new certificate when its host names change or 30 days before this one expires; copy it again then. With a certificate from a public authority (`--tls-cert`), skip this step.
4. In WHMCS, open System Settings › Servers › Add New Server:
   - Module: Sifruno.
   - Hostname: the panel's name, exactly as given to `--panel-host`. The certificate is checked against it.
   - Password: the API token (`sfr_` and 43 more characters). WHMCS stores server passwords encrypted.
   - Access Hash: the full path from step 3, or empty for a public certificate.
   - Port: leave it, for 8443, unless the panel uses another HTTPS port. Username: leave empty.
   - Click Test Connection.
5. Create a product (System Settings › Products/Services):
   - Details: tick Require Domain. The domain becomes the website's domain.
   - Module Settings: Module Name Sifruno, the server group with the panel, and the PHP version. Choose when to set up; "as soon as the first payment is received" works.
6. Optional: on the product's Custom Fields tab, add two text fields, `Sifruno account ID` and `Sifruno job ID`, with Admin Only ticked. The module keeps the website's IDs in them. If they do not exist, WHMCS creates them the first time the module saves a value.

The client sees the WordPress login as the service's username and password. To send it, use `{$service_username}` and `{$service_password}` in the product's welcome email. WordPress's admin is at `/wp-admin/` on the domain.

## How Create works

Creating a website is a panel job that takes minutes: the hosting account, the web server, the certificate, the database and the WordPress install. The panel allows a job up to 15 minutes.

WHMCS runs Create inside a payment gateway's callback, an admin's browser request or the cron. The first two give up long before the job ends, and a gateway whose callback times out sends it again. So Create does not wait for the job:

1. It starts the job. A refusal, such as a domain that already has a website, is shown at once.
2. It saves the WordPress login on the service, then the job ID.
3. It follows the job for 15 seconds, so a job that fails early is shown as a failed Create.
4. It returns success while the job runs on.

After that, every action finds the website by the account ID or job ID this service saved. Suspend, Unsuspend and Terminate never act on a website matched by domain alone, because another service may own it; a repeated Create finds what this service already started and starts nothing. While the job still runs, or after it failed, the action and the admin service page say so. A job that fails after Create returned leaves the service Active in WHMCS with no website: the admin service page shows the panel's reason. Fix the cause, then run Create again.

The panel builds one website at a time. An order that arrives while another website is being built fails with "Another website is being created right now"; run Create on that service again a few minutes later.

## Changes and revisions

Suspend, Unsuspend and Terminate send the revision the panel showed with the change. If someone changed the website in between, the panel answers 409 and changes nothing; the module reads the website again and retries, three tries in all. A change may take the panel up to 11 minutes; the module waits that long for its answer.

## Logs and secrets

Every call to the panel goes to WHMCS's module log (System Logs › Module Log, with module logging on): the method, the path, the JSON sent and the answer. The token is never in it, the WordPress password is replaced by `********`, and both are also on logModuleCall's list of values to mask. Error messages never contain them.

Certificates are always verified, and the module only speaks HTTPS. There is no setting to turn verification off.

The token can do everything an admin can do in the panel's API, except sign in and manage tokens; the panel has no token scopes yet. Keep it only in the server's Password field. To stop WHMCS using it, revoke it in Security › API tokens.

## When something fails

| Error starts with or contains | What happened | What to do next |
| --- | --- | --- |
| "The server's Password field does not hold a Sifruno API token" | The Password field is empty or not a token. Nothing was sent. | Paste the token from Security › API tokens into the server's Password field. |
| "The panel refused the API token" | The panel answered 401: the token is wrong, expired or revoked. | Create a new token in the panel and replace it in WHMCS. |
| "The panel's HTTPS certificate could not be verified" | The certificate is self-signed and the Access Hash file is missing or old, or the Hostname is not a name the certificate is for. | Copy the current `panel-cert.pem` to WHMCS, put its path in Access Hash, and use the `--panel-host` name as Hostname. |
| "The panel does not answer for the host name" | The panel answered 421: the Hostname is not one of its `--panel-host` names. | Use one of those names, or run the installer again with this name added to `--panel-host`. |
| "Nothing answered at" or "HTTPS could not be set up" | The panel is not listening there, or a firewall blocks WHMCS. | Check the Port, that the panel runs with `--panel-host`, and the panel server's firewall. |
| "Another website is being created right now" | The panel builds one website at a time. | Run Create again when the other website is done. |
| "already belongs to the hosting account" | The domain already has a website on the panel. | Use another domain, or delete that website first. |
| "does not record which website on the panel is its own" | The service's `Sifruno account ID` field is empty or names no website, and the module does not guess by domain. Nothing changed. | Open the website in the panel, copy the account ID from its page into the field, then run the action again. |
| "Creating the website failed on the panel" | The wizard job failed. The message has the panel's what, why and next step, and the job ID. | Follow the panel's next step, then run Create again. |
| "The website is still being created" | The job has not finished. | Wait, then try again. The admin service page shows the step it is on. |
| "The panel has no website for" | No website has this domain, and no job for it is kept. | Check Websites in the panel. If it was deleted there, set the service's status in WHMCS by hand. |
| "This website changed after the page loaded it" | Three tries in a row met a change from someone else. | Check the website in the panel, then try again. |
| "WHMCS did not save its WordPress login" | The website is being created, but WHMCS refused to store the login. | Do not run Create again. When the website is ready, set a new WordPress password in WordPress and put it in the service's Password field. |

## Tests

`php integrations/whmcs/tests/run.php` runs every module function against a stand-in panel (`tests/mock-panel.php`, served by `php -S` behind a small TLS proxy with a self-signed certificate). The stand-in checks the bearer token, the panel's strict JSON rules, `expected_revision` and the panel's two problem JSON shapes. `tests/stubs.php` stands in for WHMCS's own functions and records what the module logs and saves; the runner checks that no token or password is in any of it. It needs the PHP CLI with curl, json and openssl, and the `openssl` command.

`scripts/devvm/proof.sh whmcs-module` runs the module with the dev VM's lsphp PHP CLI against the real panel and broker.
