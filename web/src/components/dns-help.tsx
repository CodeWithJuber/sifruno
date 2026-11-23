// How to point a domain at this server. Shared by the wizard's last screen and
// a website's Overview, which show it under their "Set up DNS" button.
export function DnsHelp({ id, domain, hidden }: { id: string; domain: string; hidden: boolean }) {
  return <div id={id} hidden={hidden} className="rounded-md border border-border bg-muted p-4" data-testid="dns-help">
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <h3>Point {domain} at this server</h3>
        <p className="text-sm">Where you manage the domain's DNS, add this record:</p>
      </div>
      <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-1 text-sm">
        <dt className="text-muted-foreground">Type</dt><dd className="font-medium text-foreground">A</dd>
        <dt className="text-muted-foreground">Name</dt><dd className="break-words text-foreground">{domain}</dd>
        <dt className="text-muted-foreground">Points to</dt><dd className="text-foreground">This server's public IP address</dd>
      </dl>
      <p className="text-sm">Open site works once the record is live. DNS changes can take a few hours to reach everyone.</p>
    </div>
  </div>;
}
