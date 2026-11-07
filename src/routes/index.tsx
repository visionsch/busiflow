import { createFileRoute, ClientOnly } from "@tanstack/react-router";
import { Component, lazy, Suspense, type ErrorInfo, type ReactNode } from "react";
import shopflowCss from "../shopflow/index.css?url";

const App = lazy(() => import("../shopflow/App"));

class AppErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  state = { hasError: false };
  static getDerivedStateFromError() { return { hasError: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("SHOPFLOW_RENDER_ERROR", error, info.componentStack); }
  render() {
    if (this.state.hasError)
      return (
        <main role="alert" style={{ maxWidth: 640, margin: "12vh auto", padding: 24 }}>
          <h1>Something went wrong</h1>
          <p>ShopFlow could not display this screen. Your last action may not have been saved. Refresh the page and check the relevant record before trying again.</p>
          <button onClick={() => window.location.reload()}>Refresh ShopFlow</button>
        </main>
      );
    return this.props.children;
  }
}

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ShopFlow Manager — Retail & marketplace management" },
      { name: "description", content: "Run your shop's sales, stock, team, online orders and payments, and sell on the ShopFlow marketplace." },
      { property: "og:title", content: "ShopFlow Manager" },
      { property: "og:description", content: "Retail management and multi-vendor marketplace for shops." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    links: [
      { rel: "preconnect", href: "https://fonts.googleapis.com" },
      { rel: "stylesheet", href: "https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap" },
      { rel: "stylesheet", href: shopflowCss },
    ],
  }),
  component: Index,
});

function Index() {
  return (
    <ClientOnly fallback={null}>
      <AppErrorBoundary>
        <Suspense fallback={null}>
          <App />
        </Suspense>
      </AppErrorBoundary>
    </ClientOnly>
  );
}
