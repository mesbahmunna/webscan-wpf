import { useCallback, useEffect, useRef, useState } from 'react';
import {
  CheckCircle2,
  ExternalLink,
  Loader2,
  Menu,
  ShieldCheck,
  X,
  XCircle,
} from 'lucide-react';
import { DashboardSidebar, type WorkspaceView } from './components/DashboardSidebar';
import { BulkScannerWorkspace } from './components/BulkScannerWorkspace';
import { SingleScannerWorkspace } from './components/SingleScannerWorkspace';
import {
  loadActiveTaskId,
  loadSavedTasks,
  loadSavedTasksAsync,
  saveActiveTaskId,
  saveTasksAsync,
  type BulkScanTask,
} from './utils/taskStorage';

interface ApiStatusResponse {
  working: boolean;
  configured: boolean;
  provider?: string;
  message: string;
  latencyMs?: number;
}

export default function App() {
  const initialRef = useRef<{ tasks: BulkScanTask[]; activeTaskId: string | null } | null>(null);
  if (!initialRef.current) {
    const syncTasks = loadSavedTasks();
    const savedActiveId = loadActiveTaskId();
    const resolvedActiveId =
      savedActiveId && syncTasks.some((t) => t.id === savedActiveId)
        ? savedActiveId
        : null;
    initialRef.current = { tasks: syncTasks, activeTaskId: resolvedActiveId };
  }

  const [activeView, setActiveView] = useState<WorkspaceView>('bulk');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [tasks, setTasks] = useState<BulkScanTask[]>(initialRef.current.tasks);
  const [activeTaskId, setActiveTaskId] = useState<string | null>(initialRef.current.activeTaskId);
  const [scanningTaskId, setScanningTaskId] = useState<string | null>(null);
  const [checkingApi, setCheckingApi] = useState(false);
  const [apiStatus, setApiStatus] = useState<ApiStatusResponse | null>(null);
  const [showApiPopover, setShowApiPopover] = useState(false);

  const hydratedRef = useRef(false);
  const tasksRef = useRef<BulkScanTask[]>(tasks);
  tasksRef.current = tasks;

  // Hydrate unlimited saved tasks from IndexedDB on mount
  useEffect(() => {
    let cancelled = false;
    void loadSavedTasksAsync().then((loadedTasks) => {
      if (cancelled) return;
      hydratedRef.current = true;
      setTasks((current) => (current.length > 0 && loadedTasks.length === 0 ? current : loadedTasks));
      const savedActiveId = loadActiveTaskId();
      if (savedActiveId && loadedTasks.some((t) => t.id === savedActiveId)) {
        setActiveTaskId(savedActiveId);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Debounced IndexedDB persistence for large unlimited CSV tasks + immediate flush on unload
  useEffect(() => {
    if (!hydratedRef.current) return;
    const timer = window.setTimeout(() => {
      void saveTasksAsync(tasks);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [tasks]);

  useEffect(() => {
    const flushTasks = () => {
      if (hydratedRef.current) {
        void saveTasksAsync(tasksRef.current);
      }
    };
    window.addEventListener('beforeunload', flushTasks);
    return () => {
      window.removeEventListener('beforeunload', flushTasks);
      flushTasks();
    };
  }, []);

  useEffect(() => {
    if (!hydratedRef.current && activeTaskId === null) return;
    saveActiveTaskId(activeTaskId);
  }, [activeTaskId]);

  const activeTask = tasks.find((t) => t.id === activeTaskId) ?? null;

  const handleCreateTask = useCallback((newTask: BulkScanTask) => {
    hydratedRef.current = true;
    setTasks((prev) => {
      const next = [newTask, ...prev];
      void saveTasksAsync(next);
      return next;
    });
    setActiveTaskId(newTask.id);
    saveActiveTaskId(newTask.id);
    setActiveView('bulk');
  }, []);

  const handleUpdateTask = useCallback(
    (taskId: string, updater: (task: BulkScanTask) => BulkScanTask) => {
      hydratedRef.current = true;
      setTasks((prev) =>
        prev.map((task) =>
          task.id === taskId ? { ...updater(task), updatedAt: Date.now() } : task
        )
      );
    },
    []
  );

  const handleSelectTask = useCallback((taskId: string) => {
    setActiveTaskId(taskId);
    saveActiveTaskId(taskId);
    setActiveView('bulk');
  }, []);

  const handleNewTask = useCallback(() => {
    setActiveTaskId(null);
    saveActiveTaskId(null);
    setActiveView('bulk');
  }, []);

  const handleDeleteTask = useCallback((taskId: string) => {
    hydratedRef.current = true;
    setTasks((prev) => {
      const remaining = prev.filter((t) => t.id !== taskId);
      void saveTasksAsync(remaining);
      setActiveTaskId((currentActive) => {
        const nextActive = currentActive === taskId ? remaining[0]?.id ?? null : currentActive;
        saveActiveTaskId(nextActive);
        return nextActive;
      });
      return remaining;
    });
  }, []);

  const handleCheckApi = useCallback(async () => {
    if (checkingApi) return;
    setCheckingApi(true);
    setShowApiPopover(true);
    try {
      const res = await fetch('/api/check-api', { method: 'GET', cache: 'no-store' });
      const data = (await res.json().catch(() => null)) as ApiStatusResponse | null;
      if (!res.ok || !data) {
        setApiStatus({
          working: false,
          configured: false,
          message: `API check endpoint returned HTTP ${res.status}.`,
        });
      } else {
        setApiStatus(data);
      }
    } catch {
      setApiStatus({
        working: false,
        configured: false,
        message: 'Network error while contacting /api/check-api.',
      });
    } finally {
      setCheckingApi(false);
    }
  }, [checkingApi]);

  const viewTitle = activeView === 'bulk' ? 'Bulk CSV Scanner' : 'Single URL Scanner';

  return (
    <div className="min-h-screen flex bg-[#F8FAFC] text-slate-900">
      <DashboardSidebar
        activeView={activeView}
        onSelectView={setActiveView}
        tasks={tasks}
        activeTaskId={activeTaskId}
        scanningTaskId={scanningTaskId}
        onSelectTask={handleSelectTask}
        onNewTask={handleNewTask}
        onDeleteTask={handleDeleteTask}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 bg-white border-b border-slate-200/90 px-4 sm:px-8 flex items-center justify-between gap-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden w-9 h-9 inline-flex items-center justify-center rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 transition-colors cursor-pointer shrink-0"
            >
              <Menu className="w-4.5 h-4.5" aria-hidden="true" />
            </button>

            <div className="flex items-center gap-2 text-sm min-w-0">
              <span className="font-semibold text-slate-500 hidden sm:inline whitespace-nowrap">
                WordPressFixer
              </span>
              <span className="text-slate-300 hidden sm:inline" aria-hidden="true">
                /
              </span>
              <span
                className={`whitespace-nowrap ${
                  activeView === 'bulk' && activeTask
                    ? 'font-medium text-slate-500 hidden md:inline'
                    : 'font-semibold text-slate-900 truncate'
                }`}
              >
                {viewTitle}
              </span>
              {activeView === 'bulk' && activeTask && (
                <>
                  <span className="text-slate-300 hidden md:inline" aria-hidden="true">
                    /
                  </span>
                  <span
                    className="font-semibold text-slate-900 truncate"
                    data-testid="active-task-breadcrumb"
                  >
                    {activeTask.name}
                  </span>
                </>
              )}
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <div className="relative">
              <button
                type="button"
                onClick={handleCheckApi}
                disabled={checkingApi}
                data-testid="check-api-btn"
                className={`h-8 px-3 rounded-lg border text-xs font-medium inline-flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2 ${
                  apiStatus?.working
                    ? 'border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100/70'
                    : apiStatus && !apiStatus.working
                      ? 'border-red-200 bg-red-50 text-red-700 hover:bg-red-100/70'
                      : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50 hover:text-slate-900'
                }`}
              >
                {checkingApi ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                    <span>Checking API...</span>
                  </>
                ) : apiStatus?.working ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" aria-hidden="true" />
                    <span>API Working</span>
                  </>
                ) : apiStatus && !apiStatus.working ? (
                  <>
                    <XCircle className="w-3.5 h-3.5 text-red-600" aria-hidden="true" />
                    <span>API Not Working</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-3.5 h-3.5 text-slate-500" aria-hidden="true" />
                    <span>Check API</span>
                  </>
                )}
              </button>

              {showApiPopover && (checkingApi || apiStatus) && (
                <div
                  role="status"
                  data-testid="api-status-popover"
                  className="absolute right-0 mt-2 w-72 sm:w-80 rounded-xl bg-white border border-slate-200 shadow-lg p-3.5 z-40"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      {checkingApi ? (
                        <Loader2 className="w-4 h-4 animate-spin text-[#1D4ED8] shrink-0" />
                      ) : apiStatus?.working ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-600 shrink-0" />
                      )}
                      <span className="text-xs font-semibold text-slate-900">
                        {checkingApi
                          ? 'Testing Google Threat API...'
                          : apiStatus?.working
                            ? 'Google API Connected'
                            : 'Google API Not Working'}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => setShowApiPopover(false)}
                      aria-label="Close API status"
                      className="w-6 h-6 inline-flex items-center justify-center rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer shrink-0"
                    >
                      <X className="w-3.5 h-3.5" aria-hidden="true" />
                    </button>
                  </div>

                  {!checkingApi && apiStatus && (
                    <div className="mt-2 space-y-1.5 text-xs text-slate-600 leading-relaxed">
                      <p>{apiStatus.message}</p>
                      {(apiStatus.provider || apiStatus.latencyMs !== undefined) && (
                        <p className="text-[11px] font-mono tabular-nums text-slate-400">
                          {[
                            apiStatus.provider,
                            apiStatus.latencyMs !== undefined ? `${apiStatus.latencyMs}ms` : null,
                          ]
                            .filter(Boolean)
                            .join(' · ')}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>

            <a
              href="https://wordpressfixer.com/"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:inline-flex items-center gap-1.5 text-xs sm:text-sm font-medium text-slate-600 hover:text-[#1D4ED8] transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2 rounded-md py-1"
            >
              <span>wordpressfixer.com</span>
              <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
            </a>
          </div>
        </header>

        <main className="flex-1 w-full max-w-6xl mx-auto px-4 sm:px-8 py-6 sm:py-8">
          <div className={activeView === 'bulk' ? 'block' : 'hidden'}>
            <BulkScannerWorkspace
              activeTask={activeTask}
              onCreateTask={handleCreateTask}
              onUpdateTask={handleUpdateTask}
              onNewTask={handleNewTask}
              onDeleteTask={handleDeleteTask}
              onScanningTaskChange={setScanningTaskId}
            />
          </div>
          <div className={activeView === 'single' ? 'block' : 'hidden'}>
            <SingleScannerWorkspace />
          </div>
        </main>
      </div>
    </div>
  );
}
