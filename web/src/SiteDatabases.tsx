import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { cn } from "cn";
import { CircleAlert, CircleCheck, Database, ExternalLink, Eye, EyeOff, KeyRound, Plus, RefreshCw, Trash2, TriangleAlert, UserRound } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { checkConfirmName, checkDatabaseChoice, checkPassword, checkSuffix, createDatabaseUser, createSiteDatabase, databaseHost, DatabasesApiError, databasesFor, deleteDatabaseUser, deleteSiteDatabase, fullName, listSiteDatabases, openPhpMyAdmin, setDatabaseUserPassword, suffixLimit, usedByWordPress } from "@/lib/databases-api";
import type { NameKind, PhpMyAdminLink, SiteDatabase, SiteDatabases as DatabaseList } from "@/lib/databases-api";
import { getWebsite, WebsitesApiError } from "@/lib/websites-api";
import type { Website } from "@/lib/websites-api";
import { useShell } from "@/shell/context";

// One website's Databases page: its databases and database users, forms to
// make more, a password change for each user, and deletes that ask for the
// name to be typed. A password lives only in a form's state until its request
// is sent. It is never read back from the server, shown again or stored.
// The base styles colour <p> and <a> outside Tailwind's layers, so coloured
// text uses div or span, as on the other Websites screens.

const panel = "rounded-lg border border-border bg-card";
const control = "h-10 pointer-coarse:h-12";
const rowControl = "h-9 pointer-coarse:h-11";
const linkButton = (variant: "default" | "outline" | "ghost", className = "") =>
  cn(buttonVariants({ variant, className: `${rowControl} ${variant === "default" ? "text-primary-foreground!" : ""} ${className}` }));

interface Problem { what: string; why: string; next: string; technical: string; status: number }

function problemFrom(error: unknown, what: string): Problem {
  if (error instanceof DatabasesApiError || error instanceof WebsitesApiError) return { what: error.message, why: error.why, next: error.next, technical: error.technical, status: error.status };
  return { what, why: "Something unexpected went wrong in the panel.", next: "Reload the page and try again.", technical: error instanceof Error ? error.name : "unknown error", status: 0 };
}

function TechnicalDetails({ children }: { children: ReactNode }) {
  return <details className="text-sm">
    <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">Technical details</summary>
    <div className="mt-2 rounded-md border border-border bg-muted p-3 font-mono text-xs break-words whitespace-pre-wrap text-foreground">{children}</div>
  </details>;
}

// What happened (the title), why, what to do next, and the request under
// Technical details. role="alert": a failure is announced at once.
function ProblemAlert({ problem, onRetry, testId }: { problem: Problem; onRetry?: () => void; testId: string }) {
  return <Alert variant="destructive" className="text-start" data-testid={testId}>
    <CircleAlert aria-hidden="true" />
    <AlertTitle>{problem.what}</AlertTitle>
    <AlertDescription className="flex flex-col gap-3 text-start text-foreground">
      <div className="flex flex-col gap-1.5 text-sm">
        <div className="text-foreground">{problem.why}</div>
        <div className="text-muted-foreground"><span className="font-medium text-foreground">Next step:</span> {problem.next}</div>
      </div>
      <TechnicalDetails>{problem.technical}</TechnicalDetails>
      {onRetry && <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}><RefreshCw aria-hidden="true" />Try again</Button>}
    </AlertDescription>
  </Alert>;
}

// ---- One polite live region ---------------------------------------------------

// One region speaks for the whole page: a field's error a moment after the
// person leaves it, and the result of a change. Each message has an owner, so
// a field that was fixed takes back only its own announcement.
interface Announcer { say: (owner: string, message: string, delayMs: number) => void; clear: (owner: string) => void }

function useAnnouncer(): { text: string; announcer: Announcer } {
  const [text, setText] = useState("");
  const timer = useRef<number | undefined>(undefined);
  const current = useRef<string | undefined>(undefined);
  const say = useCallback((owner: string, message: string, delayMs: number) => {
    window.clearTimeout(timer.current);
    setText("");
    current.current = owner;
    // Wait until the screen reader has read what received focus.
    timer.current = window.setTimeout(() => setText(message), delayMs);
  }, []);
  const clear = useCallback((owner: string) => {
    if (current.current !== owner) return;
    window.clearTimeout(timer.current);
    setText("");
    current.current = undefined;
  }, []);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const announcer = useMemo(() => ({ say, clear }), [say, clear]);
  return { text, announcer };
}

// ---- Field feedback -----------------------------------------------------------

type Check = (value: string) => string | undefined;
type Control = HTMLInputElement | HTMLSelectElement;
interface FieldSpec { label: string; check: Check }

// Field feedback follows the browser's :user-invalid, as on New website:
// nothing is marked until the person has changed a field and left it, or
// tried to submit. aria-invalid and the error's place in aria-describedby
// follow the same state, and an error that appears on leaving a field is read
// once through the live region.
function useUserValidity<F extends string>(form: string, fields: Record<F, FieldSpec>, values: Record<F, string>, announcer: Announcer) {
  const controls = useRef<Partial<Record<F, Control | null>>>({});
  // Used where :user-invalid is missing, and after a submit attempt.
  const edited = useRef(new Set<F>());
  const interacted = useRef(new Set<F>());
  const announced = useRef(new Set<F>());
  const spec = useRef(fields);
  spec.current = fields;
  const [errors, setErrors] = useState<Partial<Record<F, string>>>({});
  const fieldId = useCallback((name: F) => `${form}-${name}`, [form]);

  const sync = useCallback((name: F, mode: "quiet" | "leave" | "submit") => {
    const el = controls.current[name];
    if (!el) return;
    if (mode === "submit") interacted.current.add(name);
    let native = false;
    try { native = el.matches(":user-invalid"); } catch { native = false; /* Older browser: rely on the interaction flags below. */ }
    const invalid = mode === "submit" || native || (interacted.current.has(name) && !el.validity.valid);
    const message = invalid ? (el.validationMessage || spec.current[name].check(el.value) || "Check this value.") : "";
    setErrors((current) => (current[name] ?? "") === message ? current : { ...current, [name]: message || undefined });
    if (invalid) {
      // After a submit the browser moves focus to the first invalid field,
      // which reads its error, so those are not announced again.
      if (mode === "submit") announced.current.add(name);
      if (mode === "leave" && !announced.current.has(name)) {
        announced.current.add(name);
        announcer.say(fieldId(name), `${spec.current[name].label}: Error: ${message}`, 500);
      }
    } else {
      announced.current.delete(name);
      announcer.clear(fieldId(name));
    }
  }, [announcer, fieldId]);

  // The rules become the fields' custom validity, so the browser's own
  // validation (and :user-invalid) applies them. A rule can depend on the
  // page's data (the databases to choose from), so this runs on every render;
  // sync changes state only when a message changes.
  useLayoutEffect(() => {
    const names = Object.keys(spec.current) as F[];
    for (const name of names) controls.current[name]?.setCustomValidity(spec.current[name].check(values[name]) ?? "");
    for (const name of names) sync(name, "quiet");
  });

  const bind = (name: F) => ({
    id: fieldId(name),
    name,
    ref: (el: Control | null) => { controls.current[name] = el; },
    onBlur: () => { if (edited.current.has(name)) interacted.current.add(name); sync(name, "leave"); },
    onInvalid: () => sync(name, "submit"),
    "aria-invalid": errors[name] ? ("true" as const) : ("false" as const),
    "aria-describedby": [`${fieldId(name)}-hint`, errors[name] ? `${fieldId(name)}-error` : ""].filter(Boolean).join(" "),
  });
  const markEdited = (name: F) => { edited.current.add(name); };
  return { errors, bind, markEdited, fieldId };
}

function FieldProblem({ id, message }: { id: string; message?: string }) {
  if (!message) return null;
  return <div id={`${id}-error`} className="flex items-start gap-1.5 text-sm text-destructive">
    <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
    <span><span className="sr-only">Error: </span>{message}</span>
  </div>;
}

function Hint({ id, children }: { id: string; children: ReactNode }) {
  return <FieldDescription id={`${id}-hint`} className="text-start">{children}</FieldDescription>;
}

type Bound = ReturnType<ReturnType<typeof useUserValidity<string>>["bind"]>;

// A name field: the hosting account's prefix, then what the person types.
function SuffixInput({ field, username, kind, value, onChange }: { field: Bound; username: string; kind: NameKind; value: string; onChange: (value: string) => void }) {
  return <div className="flex items-stretch">
    <span className="inline-flex items-center rounded-s-lg border border-e-0 border-input bg-muted px-2.5 font-mono text-sm text-muted-foreground" aria-hidden="true" data-testid={`${field.id}-prefix`}>{username}_</span>
    <Input {...field} className={`${control} min-w-0 flex-1 rounded-s-none font-mono user-invalid:border-destructive`} type="text" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={suffixLimit(kind, username)} required
      value={value} onChange={(e) => onChange(e.target.value.trim().toLowerCase())} />
  </div>;
}

function PasswordInput({ field, value, onChange }: { field: Bound; value: string; onChange: (value: string) => void }) {
  const [shown, setShown] = useState(false);
  const noteId = `${field.id}-toggle-note`;
  return <>
    <div className="flex gap-2">
      <Input {...field} className={`${control} min-w-0 flex-1 user-invalid:border-destructive`} type={shown ? "text" : "password"} autoComplete="new-password" autoCapitalize="none" autoCorrect="off" spellCheck={false} required
        value={value} onChange={(e) => onChange(e.target.value)} />
      <Button type="button" variant="outline" className={`${control} shrink-0 px-3`} aria-pressed={shown} aria-controls={field.id} aria-describedby={noteId} onClick={() => setShown((current) => !current)}>
        {shown ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}Show password
      </Button>
    </div>
    <span id={noteId} className="sr-only">Shows the password on the screen.</span>
  </>;
}

const passwordHint = "12 to 128 bytes (a plain letter or digit is 1), with no space at the start or end. Your password manager can suggest one. The panel does not keep it and cannot show it again.";

// ---- Forms --------------------------------------------------------------------

function NewDatabaseForm({ accountId, username, announcer, onCreated }: { accountId: string; username: string; announcer: Announcer; onCreated: (name: string) => void }) {
  const [values, setValues] = useState({ suffix: "" });
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const { errors, bind, markEdited, fieldId } = useUserValidity("new-database", { suffix: { label: "Database name", check: (value) => checkSuffix("database", username, value) } }, values, announcer);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setProblem(undefined);
    try {
      onCreated(await createSiteDatabase(accountId, username, values.suffix));
    } catch (error) {
      setProblem(problemFrom(error, "The database was not created."));
      setBusy(false);
    }
  };

  return <form method="post" onSubmit={(event) => void submit(event)} aria-labelledby="new-database-heading" data-testid="new-database-form">
    <FieldGroup className="gap-4">
      <h3 id="new-database-heading">New database</h3>
      <Field data-invalid={errors.suffix ? true : undefined}>
        <FieldLabel htmlFor={fieldId("suffix")}>Database name</FieldLabel>
        <Hint id={fieldId("suffix")}>
          The name starts with <code>{username}_</code>. Add up to {suffixLimit("database", username)} lowercase letters, digits or underscores.
          {values.suffix && <> Full name: <code data-testid="new-database-full-name">{fullName(username, values.suffix)}</code></>}
        </Hint>
        <SuffixInput field={bind("suffix")} username={username} kind="database" value={values.suffix} onChange={(suffix) => { markEdited("suffix"); setValues({ suffix }); }} />
        <FieldProblem id={fieldId("suffix")} message={errors.suffix} />
      </Field>
      {problem && <ProblemAlert problem={problem} testId="new-database-problem" />}
      <div>
        {/* Stays focusable while busy, so focus is not lost and a second press does nothing. */}
        <Button type="submit" className={`${control} px-4 aria-disabled:opacity-70`} disabled={busy} focusableWhenDisabled data-testid="create-database">
          <Plus aria-hidden="true" />{busy ? "Creating…" : "Create database"}
        </Button>
      </div>
    </FieldGroup>
  </form>;
}

function NewUserForm({ accountId, username, databases, announcer, onCreated }: { accountId: string; username: string; databases: SiteDatabase[]; announcer: Announcer; onCreated: (name: string, database: string) => void }) {
  // No database is chosen for the person, even when there is only one: full
  // access to the wrong database (WordPress's, say) is a mistake worth a click.
  const [values, setValues] = useState({ suffix: "", password: "", database: "" });
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const { errors, bind, markEdited, fieldId } = useUserValidity("new-user", {
    suffix: { label: "User name", check: (value) => checkSuffix("user", username, value) },
    password: { label: "Password", check: checkPassword },
    database: { label: "Database", check: (value) => checkDatabaseChoice(databases, value) },
  }, values, announcer);
  const change = (name: keyof typeof values, value: string) => { markEdited(name); setValues((current) => ({ ...current, [name]: value })); };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setProblem(undefined);
    const { suffix, password, database } = values;
    try {
      const name = await createDatabaseUser(accountId, username, { name_suffix: suffix, password, database });
      onCreated(name, database);
    } catch (error) {
      setProblem(problemFrom(error, "The database user was not created."));
      setBusy(false);
    }
  };

  return <form method="post" onSubmit={(event) => void submit(event)} aria-labelledby="new-user-heading" data-testid="new-user-form">
    <FieldGroup className="gap-4">
      <div className="flex flex-col gap-1">
        <h3 id="new-user-heading">New user</h3>
        <p className="text-sm">A database user signs in to one database and can do everything in it. All fields are required.</p>
      </div>
      <Field data-invalid={errors.suffix ? true : undefined}>
        <FieldLabel htmlFor={fieldId("suffix")}>User name</FieldLabel>
        <Hint id={fieldId("suffix")}>
          The name starts with <code>{username}_</code>. Add up to {suffixLimit("user", username)} lowercase letters, digits or underscores.
          {values.suffix && <> Full name: <code data-testid="new-user-full-name">{fullName(username, values.suffix)}</code></>}
        </Hint>
        <SuffixInput field={bind("suffix")} username={username} kind="user" value={values.suffix} onChange={(value) => change("suffix", value)} />
        <FieldProblem id={fieldId("suffix")} message={errors.suffix} />
      </Field>
      <Field data-invalid={errors.password ? true : undefined}>
        <FieldLabel htmlFor={fieldId("password")}>Password</FieldLabel>
        <Hint id={fieldId("password")}>{passwordHint}</Hint>
        <PasswordInput field={bind("password")} value={values.password} onChange={(value) => change("password", value)} />
        <FieldProblem id={fieldId("password")} message={errors.password} />
      </Field>
      <Field data-invalid={errors.database ? true : undefined}>
        <FieldLabel htmlFor={fieldId("database")}>Database</FieldLabel>
        <Hint id={fieldId("database")}>The user gets full access to this database only.</Hint>
        <NativeSelect {...bind("database")} className="w-full max-w-sm [&>select]:h-10 pointer-coarse:[&>select]:h-12" autoComplete="off" required
          value={values.database} onChange={(e) => change("database", e.target.value)}>
          <NativeSelectOption value="">Choose a database</NativeSelectOption>
          {databases.map((database) => <NativeSelectOption key={database.name} value={database.name}>{database.name}</NativeSelectOption>)}
        </NativeSelect>
        <FieldProblem id={fieldId("database")} message={errors.database} />
      </Field>
      {problem && <ProblemAlert problem={problem} testId="new-user-problem" />}
      <div>
        <Button type="submit" className={`${control} px-4 aria-disabled:opacity-70`} disabled={busy} focusableWhenDisabled data-testid="create-user">
          <Plus aria-hidden="true" />{busy ? "Creating…" : "Create user"}
        </Button>
      </div>
    </FieldGroup>
  </form>;
}

function ChangePasswordForm({ accountId, user, wordpress, announcer, onChanged, onCancel }: { accountId: string; user: string; wordpress: boolean; announcer: Announcer; onChanged: () => void; onCancel: () => void }) {
  const [values, setValues] = useState({ password: "" });
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const { errors, bind, markEdited, fieldId } = useUserValidity(`password-${user}`, { password: { label: `New password for ${user}`, check: checkPassword } }, values, announcer);
  const field = bind("password");
  // Opened from the row's button: start in the field.
  useEffect(() => { document.getElementById(fieldId("password"))?.focus(); }, [fieldId]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setProblem(undefined);
    try {
      await setDatabaseUserPassword(accountId, user, values.password);
      setValues({ password: "" });
      onChanged();
    } catch (error) {
      setProblem(problemFrom(error, "The password was not changed."));
      setBusy(false);
    }
  };

  return <form method="post" onSubmit={(event) => void submit(event)} className="rounded-md border border-border bg-muted/40 p-3" aria-label={`Change the password for ${user}`} data-testid="change-password-form">
    <FieldGroup className="gap-3">
      <Field data-invalid={errors.password ? true : undefined}>
        <FieldLabel htmlFor={field.id}>New password for <code>{user}</code></FieldLabel>
        <Hint id={field.id}>
          {passwordHint} Apps that use this user need the new password too.
          {wordpress && " WordPress on this website signs in with this user: after the change, put the new password in the site's wp-config.php, or the site stops working."}
        </Hint>
        <PasswordInput field={field} value={values.password} onChange={(password) => { markEdited("password"); setValues({ password }); }} />
        <FieldProblem id={field.id} message={errors.password} />
      </Field>
      {problem && <ProblemAlert problem={problem} testId="change-password-problem" />}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" className={`${rowControl} px-4 aria-disabled:opacity-70`} disabled={busy} focusableWhenDisabled data-testid="save-password">{busy ? "Saving…" : "Save password"}</Button>
        <Button type="button" variant="ghost" className={rowControl} disabled={busy} onClick={onCancel}>Cancel</Button>
      </div>
    </FieldGroup>
  </form>;
}

// ---- Delete, after the name is typed --------------------------------------------

interface DeleteTarget { kind: NameKind; name: string; wordpress: boolean }

const deleteCopy: Record<NameKind, { title: (name: string) => ReactNode; effect: string; wordpress: string; label: string; action: string; failed: string }> = {
  database: {
    title: (name) => <>Delete the database <code className="wrap-anywhere">{name}</code>?</>,
    effect: "This removes the database and everything stored in it. It cannot be undone. Its users are kept; delete them separately.",
    wordpress: "WordPress on this website keeps its pages, posts and settings in this database. Deleting it takes the site down.",
    label: "Database name", action: "Delete database", failed: "The database was not deleted.",
  },
  user: {
    title: (name) => <>Delete the database user <code className="wrap-anywhere">{name}</code>?</>,
    effect: "Apps that sign in to a database as this user stop working. It cannot be undone. Databases are kept.",
    wordpress: "WordPress on this website signs in to its database as this user. Deleting it takes the site down.",
    label: "User name", action: "Delete user", failed: "The database user was not deleted.",
  },
};

function DeleteForm({ accountId, target, onBusy, onDeleted, onCancel }: { accountId: string; target: DeleteTarget; onBusy: (busy: boolean) => void; onDeleted: (target: DeleteTarget) => void; onCancel: () => void }) {
  const copy = deleteCopy[target.kind];
  const [values, setValues] = useState({ confirm: "" });
  const [busy, setBusyState] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  // The page keeps the dialog open while the request is on its way.
  const setBusy = (value: boolean) => { setBusyState(value); onBusy(value); };
  // The page behind a modal dialog is hidden from assistive technology, so
  // the dialog has its own live region.
  const { text, announcer } = useAnnouncer();
  const { errors, bind, markEdited, fieldId } = useUserValidity("delete-confirm", { confirm: { label: copy.label, check: (value) => checkConfirmName(target.name, value) } }, values, announcer);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setProblem(undefined);
    try {
      await (target.kind === "database" ? deleteSiteDatabase : deleteDatabaseUser)(accountId, target.name, values.confirm);
      onBusy(false);
      onDeleted(target);
    } catch (error) {
      setProblem(problemFrom(error, copy.failed));
      setBusy(false);
    }
  };

  return <form method="post" onSubmit={(event) => void submit(event)} className="grid gap-4" data-testid="delete-form" data-kind={target.kind} data-name={target.name}>
    <DialogHeader>
      <DialogTitle className="leading-snug">{copy.title(target.name)}</DialogTitle>
      <DialogDescription className="text-start">{copy.effect}</DialogDescription>
    </DialogHeader>
    {target.wordpress && <Alert role={undefined} variant="destructive" className="text-start" data-testid="delete-wordpress-warning">
      <TriangleAlert aria-hidden="true" />
      <AlertTitle>This is the WordPress {target.kind === "database" ? "database" : "user"}</AlertTitle>
      <AlertDescription className="text-start text-foreground">{copy.wordpress}</AlertDescription>
    </Alert>}
    <Field data-invalid={errors.confirm ? true : undefined}>
      <FieldLabel htmlFor={fieldId("confirm")}>{copy.label}</FieldLabel>
      <Hint id={fieldId("confirm")}>Type <code className="wrap-anywhere text-foreground">{target.name}</code> to confirm.</Hint>
      <Input {...bind("confirm")} className={`${control} font-mono user-invalid:border-destructive`} type="text" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} required
        value={values.confirm} onChange={(e) => { markEdited("confirm"); setValues({ confirm: e.target.value }); }} />
      <FieldProblem id={fieldId("confirm")} message={errors.confirm} />
    </Field>
    {problem && <ProblemAlert problem={problem} testId="delete-problem" />}
    <DialogFooter>
      <Button type="button" variant="outline" className={rowControl} disabled={busy} onClick={onCancel} data-testid="cancel-delete">Cancel</Button>
      <Button type="submit" variant="destructive" className={`${rowControl} aria-disabled:opacity-70`} disabled={busy} focusableWhenDisabled data-testid="confirm-delete">
        <Trash2 aria-hidden="true" />{busy ? "Deleting…" : copy.action}
      </Button>
    </DialogFooter>
    <div aria-live="polite" className="sr-only">{text}</div>
  </form>;
}

// ---- phpMyAdmin -------------------------------------------------------------------

// One click opens phpMyAdmin signed in to this website's databases. The tab
// opens during the click, so a popup blocker lets it through, and gets its
// address when the panel answers; it loses its opener first. If the browser
// opened no tab, the one-time link is offered instead: it signs in once,
// within a minute.
function OpenPhpMyAdmin({ accountId, hasDatabases, announcer }: { accountId: string; hasDatabases: boolean; announcer: Announcer }) {
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<Problem>();
  const [blocked, setBlocked] = useState<PhpMyAdminLink>();
  const hintId = "open-phpmyadmin-hint";

  const open = async () => {
    if (busy || !hasDatabases) return;
    setBusy(true);
    setProblem(undefined);
    setBlocked(undefined);
    const tab = window.open("", "_blank");
    if (tab) {
      tab.opener = null;
      try {
        tab.document.title = "Opening phpMyAdmin…";
        tab.document.body.textContent = "Opening phpMyAdmin…";
      } catch {
        // The person closed the tab at once; it is checked again below.
        tab.blur();
      }
    }
    try {
      const link = await openPhpMyAdmin(accountId);
      if (tab && !tab.closed) {
        tab.location.replace(link.url);
        announcer.say("phpmyadmin", "phpMyAdmin opened in a new tab.", 500);
      } else {
        setBlocked(link);
      }
    } catch (error) {
      tab?.close();
      setProblem(problemFrom(error, "phpMyAdmin did not open."));
    } finally {
      setBusy(false);
    }
  };

  return <div className="flex flex-col gap-2" data-testid="phpmyadmin">
    <div>
      <Button type="button" variant="outline" className={`${control} px-4 aria-disabled:opacity-70`} disabled={busy || !hasDatabases} focusableWhenDisabled aria-describedby={hintId} onClick={() => void open()} data-testid="open-phpmyadmin">
        <ExternalLink className="rtl:-scale-x-100" aria-hidden="true" />{busy ? "Opening phpMyAdmin…" : "Open phpMyAdmin"}<span className="sr-only"> (opens in a new tab)</span>
      </Button>
    </div>
    <div id={hintId} className="text-sm text-muted-foreground" data-testid="open-phpmyadmin-hint">
      {hasDatabases ? "Opens in a new tab on phpMyAdmin's own address, signed in to this website's databases only, for up to an hour."
        : "Create a database first: phpMyAdmin shows this website's databases only."}
    </div>
    {hasDatabases && <div className="text-sm text-muted-foreground" data-testid="phpmyadmin-definers">
      Triggers, views and stored routines need this website's own database user: phpMyAdmin's sign-in cannot make them.
    </div>}
    {blocked && <Alert role={undefined} className="text-start" data-testid="phpmyadmin-blocked">
      <TriangleAlert aria-hidden="true" />
      <AlertTitle>Your browser did not open a new tab.</AlertTitle>
      <AlertDescription className="flex flex-col gap-2 text-start text-foreground">
        <div>It may block new tabs from this page. This link signs in to phpMyAdmin once, within a minute.</div>
        <a href={blocked.url} target="_blank" rel="noopener noreferrer" className={linkButton("default", "w-fit px-4")} onClick={() => setBlocked(undefined)} data-testid="phpmyadmin-link">
          <ExternalLink className="rtl:-scale-x-100" aria-hidden="true" />Open phpMyAdmin<span className="sr-only"> (opens in a new tab)</span>
        </a>
      </AlertDescription>
    </Alert>}
    {problem && <ProblemAlert problem={problem} testId="phpmyadmin-problem" />}
  </div>;
}

// ---- The page -------------------------------------------------------------------

interface PageData { site: Website; list: DatabaseList }

const connectionRow = "grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-1.5 text-sm";

function DatabaseRow({ database, wordpress, onDelete }: { database: SiteDatabase; wordpress: boolean; onDelete: () => void }) {
  const users = database.users;
  return <li className="flex flex-col gap-3 rounded-md border border-border p-3" data-testid="database-row" data-name={database.name}>
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Database className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <code className="font-medium wrap-anywhere text-foreground">{database.name}</code>
        {wordpress && <Badge variant="secondary">Used by WordPress</Badge>}
      </div>
      <Button variant="destructive" className={rowControl} onClick={onDelete} data-testid="delete-database">
        <Trash2 aria-hidden="true" />Delete<span className="sr-only"> the database {database.name}</span>
      </Button>
    </div>
    <dl className={connectionRow} data-testid="connection-details">
      <dt className="text-muted-foreground">Host</dt><dd className="text-foreground"><code>{databaseHost}</code></dd>
      <dt className="text-muted-foreground">Database name</dt><dd className="text-foreground"><code className="wrap-anywhere">{database.name}</code></dd>
      <dt className="text-muted-foreground">User name</dt>
      <dd className="text-foreground" data-testid="database-users">
        {users.length === 0 ? <span className="text-muted-foreground">No user has access yet. Create one under Database users.</span>
          : users.map((user, index) => <span key={user}>{index > 0 && ", "}<code className="wrap-anywhere">{user}</code></span>)}
      </dd>
      <dt className="text-muted-foreground">Password</dt><dd className="text-muted-foreground">The one chosen for that user. The panel does not keep it.</dd>
    </dl>
  </li>;
}

export function SiteDatabases({ accountId }: { accountId: string }) {
  const { revision, setPageResource } = useShell();
  const [data, setData] = useState<PageData>();
  const [problem, setProblem] = useState<Problem>();
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date>();
  const [attempt, setAttempt] = useState(0);
  const [notice, setNotice] = useState("");
  // Bumped after a create, so the form starts again untouched.
  const [formRound, setFormRound] = useState({ database: 0, user: 0 });
  const [passwordFor, setPasswordFor] = useState<string>();
  const [target, setTarget] = useState<DeleteTarget>();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteRound, setDeleteRound] = useState(0);
  const { text: spoken, announcer } = useAnnouncer();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const databasesHeading = useRef<HTMLHeadingElement>(null);
  const usersHeading = useRef<HTMLHeadingElement>(null);
  // Set once a delete worked: its row is gone, so focus goes to the list's
  // heading. Otherwise the dialog gives focus back to the button that opened it.
  const afterDelete = useRef<HTMLElement | null>(null);
  const deleting = useRef(false);

  // One read of the website and its databases, again on the header's refresh,
  // on Try again and after each change.
  useEffect(() => {
    let live = true;
    const controller = new AbortController();
    setLoading(true);
    Promise.all([getWebsite(accountId, { signal: controller.signal }), listSiteDatabases(accountId, { signal: controller.signal })]).then(
      ([site, list]) => { if (live) { setData({ site, list }); setProblem(undefined); setLoadedAt(new Date()); setLoading(false); } },
      (error: unknown) => { if (live) { setProblem(problemFrom(error, "The databases could not be loaded.")); setLoading(false); } },
    );
    return () => { live = false; controller.abort(); };
  }, [accountId, revision, attempt]);
  useEffect(() => {
    setPageResource("site-databases", { data, loading, error: problem?.what, loadedAt });
  }, [data, loading, problem, loadedAt, setPageResource]);
  const reload = () => setAttempt((value) => value + 1);

  const domain = data?.site.domain;
  // Arriving from the website's page: start at the heading, and name the tab.
  useEffect(() => {
    if (!domain) return;
    headingRef.current?.focus();
    document.title = `Databases · ${domain} · Sifruno`;
  }, [domain]);

  // A change worked: say so, read the list again, and move to the list it changed.
  const changed = (message: string, list: NameKind | "none") => {
    setNotice(message);
    announcer.say("status", message, 500);
    reload();
    if (list !== "none") (list === "database" ? databasesHeading : usersHeading).current?.focus();
  };

  if (!data) return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="site-databases">
    {problem
      ? <ProblemAlert problem={problem} onRetry={problem.status === 404 ? undefined : reload} testId="databases-problem" />
      : loading && <div className={`${panel} flex flex-col gap-4 p-5`} aria-busy="true" data-testid="databases-loading"><span className="sr-only">Loading the databases</span><Skeleton className="h-8 w-1/2" /><Skeleton className="h-28 w-full" /><Skeleton className="h-28 w-full" /></div>}
    <div aria-live="polite" className="sr-only">{spoken}</div>
  </div>;

  const { site, list } = data;
  const username = site.username;
  const openDelete = (next: DeleteTarget) => {
    afterDelete.current = null;
    setTarget(next);
    setDeleteRound((value) => value + 1);
    setDeleteOpen(true);
  };
  const deleted = (gone: DeleteTarget) => {
    afterDelete.current = (gone.kind === "database" ? databasesHeading : usersHeading).current;
    setDeleteOpen(false);
    if (passwordFor === gone.name && gone.kind === "user") setPasswordFor(undefined);
    changed(gone.kind === "database" ? `Deleted the database ${gone.name}. Its users were kept.` : `Deleted the database user ${gone.name}.`, "none");
  };

  return <div className="flex w-full max-w-3xl flex-col gap-4" data-testid="site-databases" data-account-id={site.account_id}>
    {problem && <ProblemAlert problem={{ ...problem, next: `${problem.next} The lists below are from the last successful read.` }} onRetry={reload} testId="databases-problem" />}
    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`}>
      <div className="flex flex-col gap-1">
        <h2 ref={headingRef} tabIndex={-1} className="wrap-anywhere outline-none" data-testid="databases-heading">Databases for {site.domain}</h2>
        <p className="text-sm">Each database belongs to this website. An app connects with the host, a database name, a user name and that user's password.</p>
      </div>
      <OpenPhpMyAdmin accountId={accountId} hasDatabases={list.databases.length > 0} announcer={announcer} />
      {notice && <Alert role={undefined} className="text-start" data-testid="databases-notice">
        <CircleCheck className="text-primary" aria-hidden="true" />
        <AlertTitle>{notice}</AlertTitle>
      </Alert>}
    </section>

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="databases-list-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 id="databases-list-heading" ref={databasesHeading} tabIndex={-1} className="outline-none">Databases</h3>
        <span className="text-sm text-muted-foreground" data-testid="databases-count">{list.databases.length === 1 ? "1 database" : `${list.databases.length} databases`}</span>
      </div>
      {list.databases.length === 0
        ? <Empty className="border border-dashed border-border py-8" data-testid="databases-empty">
          <EmptyHeader>
            <EmptyMedia variant="icon"><Database aria-hidden="true" /></EmptyMedia>
            <EmptyTitle>No databases yet</EmptyTitle>
            <EmptyDescription>This website has no database. Create one below, then create a user for the app that will use it.</EmptyDescription>
          </EmptyHeader>
        </Empty>
        // role="list" keeps list semantics in Safari once list markers are removed.
        : <ul role="list" aria-labelledby="databases-list-heading" className="flex flex-col gap-3" data-testid="databases-list">
          {list.databases.map((database) => <DatabaseRow key={database.name} database={database} wordpress={usedByWordPress(username, database.name)}
            onDelete={() => openDelete({ kind: "database", name: database.name, wordpress: usedByWordPress(username, database.name) })} />)}
        </ul>}
      <Separator />
      <NewDatabaseForm key={formRound.database} accountId={accountId} username={username} announcer={announcer}
        onCreated={(name) => { setFormRound((current) => ({ ...current, database: current.database + 1 })); changed(`Created the database ${name}.`, "database"); }} />
    </section>

    <section className={`${panel} flex flex-col gap-4 p-5 md:p-6`} aria-labelledby="users-list-heading">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 id="users-list-heading" ref={usersHeading} tabIndex={-1} className="outline-none">Database users</h3>
        <span className="text-sm text-muted-foreground" data-testid="users-count">{list.users.length === 1 ? "1 user" : `${list.users.length} users`}</span>
      </div>
      {list.users.length === 0
        ? <Empty className="border border-dashed border-border py-8" data-testid="users-empty">
          <EmptyHeader>
            <EmptyMedia variant="icon"><UserRound aria-hidden="true" /></EmptyMedia>
            <EmptyTitle>No database users yet</EmptyTitle>
            <EmptyDescription>{list.databases.length === 0 ? "Create a database first. A user is always given access to one database." : "An app needs a user to sign in to a database. Create one below."}</EmptyDescription>
          </EmptyHeader>
        </Empty>
        : <ul role="list" aria-labelledby="users-list-heading" className="flex flex-col gap-3" data-testid="users-list">
          {list.users.map((user) => {
            const access = databasesFor(list.databases, user.name);
            const wordpress = usedByWordPress(username, user.name);
            const open = passwordFor === user.name;
            const formId = `password-form-${user.name}`;
            const toggleId = `password-toggle-${user.name}`;
            return <li key={user.name} className="flex flex-col gap-3 rounded-md border border-border p-3" data-testid="user-row" data-name={user.name}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <UserRound className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <code className="font-medium wrap-anywhere text-foreground">{user.name}</code>
                  {wordpress && <Badge variant="secondary">Used by WordPress</Badge>}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button id={toggleId} variant="outline" className={rowControl} aria-expanded={open} aria-controls={formId} onClick={() => setPasswordFor(open ? undefined : user.name)} data-testid="change-password">
                    <KeyRound aria-hidden="true" />Change password<span className="sr-only"> for {user.name}</span>
                  </Button>
                  <Button variant="destructive" className={rowControl} onClick={() => openDelete({ kind: "user", name: user.name, wordpress })} data-testid="delete-user">
                    <Trash2 aria-hidden="true" />Delete<span className="sr-only"> the database user {user.name}</span>
                  </Button>
                </div>
              </div>
              <div className="text-sm text-muted-foreground" data-testid="user-access">
                {access.length === 0 ? "Has access to no database. To give access, delete this user and create it again for a database."
                  : <>Full access to {access.map((name, index) => <span key={name}>{index > 0 && ", "}<code className="wrap-anywhere text-foreground">{name}</code></span>)}</>}
              </div>
              <div id={formId} hidden={!open}>
                {open && <ChangePasswordForm accountId={accountId} user={user.name} wordpress={wordpress} announcer={announcer}
                  onCancel={() => { setPasswordFor(undefined); document.getElementById(toggleId)?.focus(); }}
                  onChanged={() => { setPasswordFor(undefined); changed(`Changed the password for ${user.name}.`, "user"); }} />}
              </div>
            </li>;
          })}
        </ul>}
      <Separator />
      {list.databases.length === 0
        ? <div className="flex flex-col gap-1" data-testid="new-user-needs-database">
          <h3>New user</h3>
          <p className="text-sm">Create a database first. A user is always given access to one database.</p>
        </div>
        : <NewUserForm key={formRound.user} accountId={accountId} username={username} databases={list.databases} announcer={announcer}
          onCreated={(name, database) => { setFormRound((current) => ({ ...current, user: current.user + 1 })); changed(`Created the database user ${name} with full access to ${database}.`, "user"); }} />}
    </section>

    {/* A closed dialog keeps its last target, so its text does not vanish while it fades out. */}
    <Dialog open={deleteOpen} onOpenChange={(open) => { if (!open && !deleting.current) setDeleteOpen(false); }}>
      <DialogContent showCloseButton={false} className="sm:max-w-md" data-testid="delete-dialog"
        initialFocus={() => document.getElementById("delete-confirm-confirm") ?? true}
        finalFocus={() => afterDelete.current ?? true}>
        {target && <DeleteForm key={deleteRound} accountId={accountId} target={target} onBusy={(busy) => { deleting.current = busy; }} onDeleted={deleted} onCancel={() => setDeleteOpen(false)} />}
      </DialogContent>
    </Dialog>
    <div aria-live="polite" className="sr-only" data-testid="databases-announcer">{spoken}</div>
  </div>;
}
