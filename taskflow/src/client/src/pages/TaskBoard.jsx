/**
 * TaskBoard Page
 * Main kanban-style board view for managing tasks.
 * Handles drag-and-drop, inline editing, filtering, and real-time updates.
 */
import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import api from '../utils/api';
import TaskCard from '../components/TaskCard';
import TaskModal from '../components/TaskModal';
import FilterBar from '../components/FilterBar';
import { STATUS_CONFIG, PRIORITY_COLORS, debounce, formatDate } from '../utils/helpers';

const COLUMNS = ['todo', 'in_progress', 'review', 'done'];

export default function TaskBoard() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // State — this component manages the full board lifecycle
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState(searchParams.get('q') || '');
  const [searchResults, setSearchResults] = useState(null);
  const [selectedTask, setSelectedTask] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [draggedTask, setDraggedTask] = useState(null);
  const [dropTarget, setDropTarget] = useState(null);
  const [filter, setFilter] = useState({
    priority: searchParams.get('priority') || '',
    assignee: searchParams.get('assignee') || '',
  });
  const [stats, setStats] = useState(null);
  const [isCreating, setIsCreating] = useState(false);
  const [newTask, setNewTask] = useState({ title: '', priority: 'medium', status: 'todo' });
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState('desc');
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const boardRef = useRef(null);

  // Fetch tasks on mount and when filters change
  useEffect(() => {
    fetchTasks();
    fetchStats();
  }, [filter, page]);

  const fetchTasks = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page: String(page),
        limit: '100',
        ...(filter.priority && { priority: filter.priority }),
      });

      const { data } = await api.get(`/tasks?${params}`);
      setTasks(prev => page === 1 ? data.tasks : [...prev, ...data.tasks]);
      setHasMore(data.pagination.page < data.pagination.pages);
      setError(null);
    } catch (err) {
      setError('Failed to load tasks. Please try again.');
      console.error('Task fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const { data } = await api.get('/tasks/stats');
      setStats(data.stats);
    } catch (err) {
      console.error('Stats fetch error:', err);
    }
  };

  // Search with debouncing
  const performSearch = useCallback(
    debounce(async (query) => {
      if (!query.trim()) {
        setSearchResults(null);
        return;
      }

      try {
        const { data } = await api.get(`/tasks/search?q=${encodeURIComponent(query)}&sort=${sortBy}&order=${sortOrder}`);
        setSearchResults(data.results);
      } catch (err) {
        console.error('Search error:', err);
      }
    }, 300),
    [sortBy, sortOrder]
  );

  useEffect(() => {
    performSearch(searchQuery);
    if (searchQuery) {
      setSearchParams({ q: searchQuery });
    } else {
      setSearchParams({});
    }
  }, [searchQuery]);

  // Drag and drop handlers
  const handleDragStart = (task) => setDraggedTask(task);
  const handleDragOver = (e, status) => { e.preventDefault(); setDropTarget(status); };
  const handleDragLeave = () => setDropTarget(null);

  const handleDrop = async (e, newStatus) => {
    e.preventDefault();
    setDropTarget(null);

    if (!draggedTask || draggedTask.status === newStatus) {
      setDraggedTask(null);
      return;
    }

    // Optimistic update
    setTasks(prev =>
      prev.map(t => t.id === draggedTask.id ? { ...t, status: newStatus } : t)
    );

    try {
      await api.put(`/tasks/${draggedTask.id}`, { status: newStatus });
      fetchStats();
    } catch (err) {
      // Revert on failure
      setTasks(prev =>
        prev.map(t => t.id === draggedTask.id ? { ...t, status: draggedTask.status } : t)
      );
      setError('Failed to update task status');
    }

    setDraggedTask(null);
  };

  // Create task inline
  const handleCreateTask = async (e) => {
    e.preventDefault();
    if (!newTask.title.trim()) return;

    try {
      const { data } = await api.post('/tasks', newTask);
      setTasks(prev => [data.task, ...prev]);
      setNewTask({ title: '', priority: 'medium', status: 'todo' });
      setIsCreating(false);
      fetchStats();
    } catch (err) {
      setError('Failed to create task');
    }
  };

  // Delete task
  const handleDeleteTask = async (taskId) => {
    if (!window.confirm('Are you sure you want to delete this task?')) return;
    try {
      await api.delete(`/tasks/${taskId}`);
      setTasks(prev => prev.filter(t => t.id !== taskId));
      if (selectedTask?.id === taskId) {
        setSelectedTask(null);
        setIsModalOpen(false);
      }
      fetchStats();
    } catch (err) {
      setError('Failed to delete task');
    }
  };

  // Grouped tasks by column
  const displayTasks = searchResults || tasks;
  const groupedTasks = useMemo(() => {
    const grouped = {};
    COLUMNS.forEach(col => { grouped[col] = []; });

    displayTasks.forEach(task => {
      if (grouped[task.status]) {
        if (!filter.assignee || task.assignee_id === filter.assignee) {
          grouped[task.status].push(task);
        }
      }
    });

    return grouped;
  }, [displayTasks, filter.assignee]);

  if (loading && tasks.length === 0) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Task Board</h1>
            {stats && (
              <p className="text-sm text-gray-500 mt-1">
                {stats.total} tasks · {stats.in_progress} in progress · {stats.done} completed
              </p>
            )}
          </div>
          <div className="flex items-center space-x-3">
            <input
              type="text"
              placeholder="Search tasks..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="px-4 py-2 border rounded-lg w-64 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={() => setIsCreating(true)}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              + New Task
            </button>
          </div>
        </div>
        <FilterBar filter={filter} onChange={setFilter} />
      </div>

      {error && (
        <div className="mx-6 mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          {error}
          <button onClick={() => setError(null)} className="ml-2 underline">Dismiss</button>
        </div>
      )}

      {/* Kanban Board */}
      <div ref={boardRef} className="flex gap-4 p-6 overflow-x-auto min-h-[calc(100vh-160px)]">
        {COLUMNS.map(status => (
          <div
            key={status}
            className={`flex-1 min-w-[280px] max-w-[350px] rounded-xl p-3 ${
              dropTarget === status ? 'bg-blue-50 ring-2 ring-blue-300' : 'bg-gray-100'
            }`}
            onDragOver={(e) => handleDragOver(e, status)}
            onDragLeave={handleDragLeave}
            onDrop={(e) => handleDrop(e, status)}
          >
            <div className="flex items-center justify-between mb-3 px-1">
              <div className="flex items-center space-x-2">
                <span style={{ color: STATUS_CONFIG[status].color }}>
                  {STATUS_CONFIG[status].icon}
                </span>
                <h2 className="font-semibold text-gray-700">{STATUS_CONFIG[status].label}</h2>
                <span className="text-xs bg-gray-200 text-gray-600 px-2 py-0.5 rounded-full">
                  {groupedTasks[status]?.length || 0}
                </span>
              </div>
            </div>

            <div className="space-y-2">
              {groupedTasks[status]?.map(task => (
                <TaskCard
                  key={task.id}
                  task={task}
                  onDragStart={() => handleDragStart(task)}
                  onClick={() => { setSelectedTask(task); setIsModalOpen(true); }}
                  onDelete={() => handleDeleteTask(task.id)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Task Detail Modal */}
      {isModalOpen && selectedTask && (
        <TaskModal
          task={selectedTask}
          onClose={() => { setIsModalOpen(false); setSelectedTask(null); }}
          onUpdate={(updated) => {
            setTasks(prev => prev.map(t => t.id === updated.id ? updated : t));
            setSelectedTask(updated);
          }}
        />
      )}
    </div>
  );
}

