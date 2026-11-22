import { useCallback, useEffect, useRef, useState } from 'react';
import { ExternalLink, Menu } from 'lucide-react';
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

          <a
            href="https://wordpressfixer.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs sm:text-sm font-medium text-slate-600 hover:text-[#1D4ED8] transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2 rounded-md py-1"
          >
            <span>wordpressfixer.com</span>
            <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
          </a>
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
