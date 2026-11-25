package hostaccounts

import (
	"bytes"
	"context"
	"time"
)

// PlaceholderInput asks the broker to put a placeholder page into a live
// site whose public_html is empty. The page is fixed here; the caller sends
// only the account's revision.
type PlaceholderInput struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

// PlaceholderResult says whether the page was written. False means
// public_html already held something, even one hidden file, so nothing was
// written and the tenant's files are as they were.
type PlaceholderResult struct {
	Written bool `json:"written"`
}

// PlaceholderService is implemented by the client; the broker serves it from
// the store.
type PlaceholderService interface {
	InstallPlaceholder(ctx context.Context, id string, in PlaceholderInput, actor string) (PlaceholderResult, error)
}

// placeholderTimeout bounds the PHP run, which writes one small file. Like
// the WordPress install it does not follow the caller.
const placeholderTimeout = time.Minute

// placeholderPage is public_html/index.php for a new PHP site. The text
// "It runs PHP." appears only when PHP runs the file, so a check of the
// served page also shows that the site's PHP works. It names neither the
// account nor the PHP version, because anyone can read it.
const placeholderPage = `<?php
// A placeholder page from the hosting panel. Replace it with your
// website's own files.
header('Cache-Control: no-cache');
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Website ready</title>
<style>body{font-family:system-ui,sans-serif;line-height:1.5;max-inline-size:36rem;margin-block:4rem;margin-inline:auto;padding-inline:1rem}</style>
</head>
<body>
<h1>This website is ready</h1>
<p><?php echo 'It runs', ' PHP.'; ?> Upload the website's files to replace this page.</p>
</body>
</html>
`

// placeholderScript runs with the site's PHP CLI (php -n -r) as the
// account's user, in public_html, and reads the page on stdin. It writes
// index.php only into an empty folder and only as a new file (fopen "x" is
// O_CREAT|O_EXCL, so it never follows or replaces a link or a file made
// meanwhile), then sets it to 0644 so the web server can read it. Its last
// line is "written" or "kept"; anything else is a failure.
const placeholderScript = `$entries = @scandir('.');
if ($entries === false) { fwrite(STDERR, "public_html could not be read\n"); exit(3); }
if (count(array_diff($entries, ['.', '..'])) > 0) { echo "kept\n"; exit(0); }
$f = @fopen('index.php', 'x');
if ($f === false) {
  if (file_exists('index.php') || is_link('index.php')) { echo "kept\n"; exit(0); }
  fwrite(STDERR, "index.php could not be created\n"); exit(4);
}
$page = stream_get_contents(STDIN);
$ok = is_string($page) && $page !== '' && fwrite($f, $page) === strlen($page);
$ok = fclose($f) && $ok;
if (!$ok || !chmod('index.php', 0644)) { @unlink('index.php'); fwrite(STDERR, "index.php could not be written\n"); exit(5); }
echo "written\n";
`

// placeholderOutcome reads the script's answer: the last line of what it
// printed, with a zero exit code. A failure is an *InstallError for the
// "placeholder" step with the end of the output.
func placeholderOutcome(out []byte, code int) (bool, error) {
	text := bytes.TrimSpace(out)
	if i := bytes.LastIndexByte(text, '\n'); i >= 0 {
		text = bytes.TrimSpace(text[i+1:])
	}
	if code == 0 {
		switch string(text) {
		case "written":
			return true, nil
		case "kept":
			return false, nil
		}
	}
	return false, &InstallError{Step: "placeholder", Detail: installDetail(out)}
}
