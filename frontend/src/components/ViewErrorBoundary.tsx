import { Component, type ErrorInfo, type ReactNode } from "react";

interface ViewErrorBoundaryProps {
  resetKey: string;
  title?: string;
  onRetry?: () => void;
  onDeleteBot?: () => void;
  children: ReactNode;
}

interface ViewErrorBoundaryState {
  hasError: boolean;
  errorMessage: string;
}

export class ViewErrorBoundary extends Component<
  ViewErrorBoundaryProps,
  ViewErrorBoundaryState
> {
  state: ViewErrorBoundaryState = {
    hasError: false,
    errorMessage: "",
  };

  static getDerivedStateFromError(error: Error): ViewErrorBoundaryState {
    return {
      hasError: true,
      errorMessage: error?.message || "Unexpected rendering error.",
    };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("View render error:", error, info.componentStack);
  }

  componentDidUpdate(prevProps: ViewErrorBoundaryProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.hasError) {
      this.setState({ hasError: false, errorMessage: "" });
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="h-full flex items-center justify-center p-6">
          <div className="max-w-md w-full rounded-2xl border border-rose-200 bg-white p-5 space-y-3 shadow-xs">
            <div className="text-sm font-semibold text-slate-900">
              {this.props.title || "Unable to display this view cleanly"}
            </div>
            <p className="text-xs text-slate-600 break-words">
              {this.state.errorMessage || "A rendering error occurred in this view."}
            </p>
            <div className="flex items-center gap-2 pt-1 flex-wrap">
              <button
                type="button"
                onClick={() => {
                  this.setState({ hasError: false, errorMessage: "" });
                  this.props.onRetry?.();
                }}
                className="px-3 py-1.5 rounded-xl bg-slate-900 text-white text-xs font-medium cursor-pointer hover:bg-slate-800"
              >
                Reload View
              </button>
              {this.props.onDeleteBot && (
                <button
                  type="button"
                  onClick={() => this.props.onDeleteBot?.()}
                  className="px-3 py-1.5 rounded-xl border border-rose-200 bg-rose-50 text-rose-700 text-xs font-medium cursor-pointer hover:bg-rose-100"
                >
                  Delete Bot
                </button>
              )}
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
