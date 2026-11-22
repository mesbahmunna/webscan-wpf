import {
  ExternalLink,
  FileSpreadsheet,
  Globe,
  Loader2,
  Plus,
  Trash2,
  X,
} from 'lucide-react';
import { summarizeTaskProgress, type BulkScanTask } from '../utils/taskStorage';

export type WorkspaceView = 'bulk' | 'single';

interface DashboardSidebarProps {
  activeView: WorkspaceView;
  onSelectView: (view: WorkspaceView) => void;
  tasks: BulkScanTask[];
  activeTaskId: string | null;
  scanningTaskId: string | null;
  onSelectTask: (taskId: string) => void;
  onNewTask: () => void;
  onDeleteTask: (taskId: string) => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export function DashboardSidebar({
  activeView,
  onSelectView,
  tasks,
  activeTaskId,
  scanningTaskId,
  onSelectTask,
  onNewTask,
  onDeleteTask,
  mobileOpen,
  onCloseMobile,
}: DashboardSidebarProps) {
  const navItems: Array<{ id: WorkspaceView; label: string; icon: typeof FileSpreadsheet }> = [
    { id: 'bulk', label: 'Bulk CSV Scanner', icon: FileSpreadsheet },
    { id: 'single', label: 'Single URL Scanner', icon: Globe },
  ];

  const handleSelectView = (view: WorkspaceView) => {
    onSelectView(view);
    onCloseMobile();
  };

  const handleSelectTask = (taskId: string) => {
    onSelectTask(taskId);
    onCloseMobile();
  };

  const handleNewTask = () => {
    onNewTask();
    onCloseMobile();
  };

  const sidebarContent = (
    <div className="flex flex-col h-full bg-white border-r border-slate-200 w-64 shrink-0">
      <div className="h-16 px-5 flex items-center justify-between border-b border-slate-200/90 shrink-0">
        <a
          href="https://wordpressfixer.com/"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2.5 text-slate-900 hover:opacity-90 transition-opacity whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2 rounded-md"
        >
          <span
            className="w-8 h-8 rounded-lg bg-[#1D4ED8] flex items-center justify-center shrink-0 shadow-[inset_0_1px_0_rgba(255,255,255,0.2)]"
            aria-hidden="true"
          >
            <svg
              viewBox="0 0 24 24"
              className="w-4.5 h-4.5 text-white"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </span>
          <span className="text-[16px] font-bold tracking-tight text-slate-900">
            WordPress<span className="text-[#1D4ED8]">Fixer</span>
          </span>
        </a>

        <button
          type="button"
          onClick={onCloseMobile}
          aria-label="Close navigation menu"
          className="lg:hidden w-8 h-8 inline-flex items-center justify-center rounded-md text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" aria-hidden="true" />
        </button>
      </div>

      <nav aria-label="Scanner workspace navigation" className="px-3 py-4 space-y-1 shrink-0">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => handleSelectView(item.id)}
              aria-current={isActive ? 'page' : undefined}
              className={`w-full h-10 px-3 rounded-lg flex items-center gap-2.5 text-sm font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] ${
                isActive
                  ? 'bg-[#EFF6FF] text-[#1D4ED8]'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100/80'
              }`}
            >
              <Icon
                className={`w-4 h-4 shrink-0 ${isActive ? 'text-[#1D4ED8]' : 'text-slate-400'}`}
                aria-hidden="true"
              />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Saved Bulk Scan Tasks */}
      <div className="flex-1 min-h-0 flex flex-col border-t border-slate-200/80 pt-4">
        <div className="px-4 pb-2 flex items-center justify-between gap-2 shrink-0">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Saved Tasks
          </span>
          <button
            type="button"
            onClick={handleNewTask}
            data-testid="sidebar-new-task-btn"
            aria-label="Create new bulk scan task"
            className="h-6 px-2 rounded-md text-xs font-semibold text-[#1D4ED8] hover:bg-[#EFF6FF] inline-flex items-center gap-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8]"
          >
            <Plus className="w-3.5 h-3.5" aria-hidden="true" />
            <span>New</span>
          </button>
        </div>

        <div
          className="flex-1 overflow-y-auto px-3 pb-4 space-y-1"
          data-testid="saved-tasks-list"
        >
          {tasks.length === 0 ? (
            <p className="px-2 py-2 text-xs text-slate-400 leading-relaxed">
              Uploaded CSV batches are saved here automatically across reloads.
            </p>
          ) : (
            tasks.map((task) => {
              const summary = summarizeTaskProgress(task.rows);
              const isSelected = activeView === 'bulk' && activeTaskId === task.id;
              const isTaskScanning = scanningTaskId === task.id;

              return (
                <div
                  key={task.id}
                  data-testid="saved-task-item"
                  className={`group flex items-start gap-1 rounded-lg transition-colors ${
                    isSelected
                      ? 'bg-[#EFF6FF]/90 text-[#1E3A8A]'
                      : 'text-slate-700 hover:bg-slate-100/75'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => handleSelectTask(task.id)}
                    aria-current={isSelected ? 'true' : undefined}
                    className="flex-1 min-w-0 text-left px-2.5 py-2 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] rounded-lg"
                  >
                    <div className="flex items-center gap-1.5 min-w-0">
                      {isTaskScanning && (
                        <Loader2
                          className="w-3 h-3 animate-spin text-[#1D4ED8] shrink-0"
                          aria-hidden="true"
                        />
                      )}
                      <span
                        className={`text-xs font-semibold truncate ${
                          isSelected ? 'text-[#1D4ED8]' : 'text-slate-800'
                        }`}
                      >
                        {task.name}
                      </span>
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5 text-[11px] font-mono tabular-nums text-slate-500">
                      <span>
                        {summary.scannedCount}/{summary.validCount}
                      </span>
                      {summary.failedOrErrorCount > 0 ? (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="text-red-600 font-medium">
                            {summary.failedOrErrorCount} failed
                          </span>
                        </>
                      ) : summary.scannedCount > 0 && summary.pendingCount === 0 ? (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="text-emerald-600 font-medium">Clean</span>
                        </>
                      ) : null}
                    </div>
                  </button>

                  <button
                    type="button"
                    disabled={isTaskScanning}
                    onClick={() => onDeleteTask(task.id)}
                    aria-label={`Delete task ${task.name}`}
                    className="mt-1.5 mr-1 w-7 h-7 inline-flex items-center justify-center rounded-md text-slate-400 opacity-70 group-hover:opacity-100 hover:text-red-600 hover:bg-red-50 disabled:opacity-30 disabled:cursor-not-allowed transition-colors shrink-0 cursor-pointer focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-600"
                  >
                    <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                  </button>
                </div>
              );
            })
          )}
        </div>
      </div>

      <div className="px-5 py-4 border-t border-slate-200/80 shrink-0">
        <a
          href="https://wordpressfixer.com/"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 hover:text-[#1D4ED8] transition-colors whitespace-nowrap"
        >
          <span>wordpressfixer.com</span>
          <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
        </a>
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden lg:flex lg:shrink-0 lg:sticky lg:top-0 lg:h-screen">
        {sidebarContent}
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-slate-900/35"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <div className="relative z-10 flex h-full">{sidebarContent}</div>
        </div>
      )}
    </>
  );
}
