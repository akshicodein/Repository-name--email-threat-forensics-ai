import React from 'react';
import { ShieldAlert, RefreshCw, ArrowLeft, Terminal } from 'lucide-react';
import { Button } from './Button';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('SOC ErrorBoundary caught exception:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[60vh] flex flex-col items-center justify-center text-center p-6 font-mono">
          <div className="p-4 rounded-2xl bg-rose-950/40 border border-rose-800/80 text-rose-400 mb-5 shadow-2xl">
            <ShieldAlert className="w-10 h-10 animate-pulse" />
          </div>
          <h2 className="text-xl font-bold text-slate-100 uppercase tracking-wide">
            INVESTIGATION VIEW ENCOUNTERED AN UNEXPECTED ERROR
          </h2>
          <p className="text-xs text-slate-400 mt-2 max-w-md font-sans">
            The forensics rendering layer caught a rendering anomaly. The application state remains protected.
          </p>

          <div className="flex items-center gap-3 mt-6">
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.reload()}
              icon={RefreshCw}
            >
              Reload Application
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={this.handleReset}
              icon={ArrowLeft}
            >
              Return to Ingestion
            </Button>
          </div>

          <div className="mt-8 text-[11px] text-slate-400 flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyan-500" />
            <span>SOC Incident Handler • State Protected</span>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
