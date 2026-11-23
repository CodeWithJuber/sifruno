import { useId } from "react";
import { Autocomplete } from "@base-ui/react/autocomplete";
import { Dialog } from "@base-ui/react/dialog";
import { Search } from "lucide-react";
import { Kbd } from "@/components/ui/kbd";

// Ctrl+K opens any page or action (plan, UX rule 8). Built from Base UI's
// Autocomplete and Dialog: shadcn's Command needs cmdk, which is not on the
// plan's approved dependency list.

export interface Command {
  id: string;
  label: string;
  hint: string;
  search: string;
  run: () => void;
}

export interface CommandGroup {
  value: string;
  items: Command[];
}

export function CommandPalette({ open, onOpenChange, groups }: { open: boolean; onOpenChange: (open: boolean) => void; groups: CommandGroup[] }) {
  const helpId = useId();
  const choose = (command: Command) => {
    onOpenChange(false);
    command.run();
  };
  return <Dialog.Root open={open} onOpenChange={onOpenChange}>
    <Dialog.Portal>
      <Dialog.Backdrop className="fixed inset-0 z-50 bg-black/30 transition-opacity duration-150 data-ending-style:opacity-0 data-starting-style:opacity-0" />
      <Dialog.Viewport className="fixed inset-0 z-50 flex items-start justify-center overflow-hidden px-2 pt-[12vh] pb-2">
        <Dialog.Popup aria-label="Search pages and actions" className="relative flex max-h-[min(32rem,calc(100dvh-5rem))] w-[calc(100vw-1rem)] max-w-lg flex-col overflow-hidden rounded-lg border border-border bg-card text-foreground shadow-lg outline-none transition-[translate,opacity] duration-150 data-ending-style:-translate-y-2 data-ending-style:opacity-0 data-starting-style:-translate-y-2 data-starting-style:opacity-0">
          <Autocomplete.Root open inline items={groups} autoHighlight="always" keepHighlight itemToStringValue={(item: Command) => item.search}>
            <Autocomplete.InputGroup className="flex items-center gap-2 border-b border-border px-3 focus-within:border-b-primary">
              <Search className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <Autocomplete.Input data-slot="command-input" aria-label="Search pages and actions" aria-describedby={helpId} placeholder="Search pages and actions…" className="h-11 w-full border-0 bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground" />
            </Autocomplete.InputGroup>
            <Dialog.Close className="sr-only">Close search</Dialog.Close>
            <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
              <Autocomplete.Empty><p className="px-4 py-8 text-sm text-muted-foreground">Nothing matches. Try a page name such as "Websites" or "Backups".</p></Autocomplete.Empty>
              <Autocomplete.List className="py-1">
                {(group: CommandGroup) => <Autocomplete.Group key={group.value} items={group.items} className="not-last:mb-1">
                  <Autocomplete.GroupLabel className="px-3 pt-2 pb-1 text-xs font-medium text-muted-foreground">{group.value}</Autocomplete.GroupLabel>
                  <Autocomplete.Collection>
                    {(command: Command) => <Autocomplete.Item key={command.id} value={command} onClick={() => choose(command)} data-testid={`command-${command.id}`}
                      className="mx-1 grid min-h-9 cursor-default grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-md px-3 text-sm outline-none select-none data-highlighted:bg-secondary data-highlighted:text-foreground">
                      <span className="truncate">{command.label}</span>
                      <span className="text-xs text-muted-foreground">{command.hint}</span>
                    </Autocomplete.Item>}
                  </Autocomplete.Collection>
                </Autocomplete.Group>}
              </Autocomplete.List>
            </div>
            <div className="flex items-center gap-2 border-t border-border px-3 py-2 text-xs text-muted-foreground">
              <span id={helpId}>Press <Kbd>Enter</Kbd> to open the highlighted item, <Kbd>Esc</Kbd> to close.</span>
            </div>
          </Autocomplete.Root>
        </Dialog.Popup>
      </Dialog.Viewport>
    </Dialog.Portal>
  </Dialog.Root>;
}
