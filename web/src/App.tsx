import { RouterProvider } from "@tanstack/react-router";
import { router } from "@/router";

export type { SiteHandoff } from "@/shell/context";

export function App() {
  return <RouterProvider router={router} />;
}
