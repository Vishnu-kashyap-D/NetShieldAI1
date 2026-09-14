import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Catches any render-time throw anywhere below it (a malformed API response hitting an
 * untyped call, a null the code didn't expect, etc.) and shows a recoverable message
 * instead of unmounting the whole app to a blank white screen. React error boundaries
 * only work as class components -- there's no hook equivalent.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled error in the dashboard UI:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div
          role="alert"
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            gap: 12,
            height: "100vh",
            padding: 24,
            textAlign: "center",
          }}
        >
          <div className="error-state" style={{ maxWidth: 480 }}>
            <div style={{ fontWeight: 600, marginBottom: 6 }}>Something went wrong in the dashboard.</div>
            <div>{this.state.error.message}</div>
          </div>
          <button className="btn" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
