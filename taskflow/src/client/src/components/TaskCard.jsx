/**
 * TaskCard Component
 * Renders a single task card in the kanban board.
 * Supports drag-and-drop and shows priority, assignee, and due date.
 */
import React from 'react';
import { PRIORITY_COLORS, formatDate, truncate } from '../utils/helpers';

// Default avatar — base64-encoded SVG placeholder
// (saves an HTTP request vs loading from CDN for each unset avatar)
const DEFAULT_AVATAR_SVG = 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSI+PGNpcmNsZSBjeD0iMjAiIGN5PSIyMCIgcj0iMjAiIGZpbGw9IiNFNUU3RUIiLz48cGF0aCBkPSJNMjAgMjBjMy4zIDAgNi0yLjcgNi02cy0yLjctNi02LTYtNiAyLjctNiA2IDIuNyA2IDYgNnptMCAyYy00IDAtMTIgMi0xMiA2djJoMjR2LTJjMC00LTgtNi0xMi02eiIgZmlsbD0iIzlDQTNBRiIvPjwvc3ZnPg==';

export default function TaskCard({ task, onDragStart, onClick, onDelete }) {
  const priorityStyle = PRIORITY_COLORS[task.priority] || PRIORITY_COLORS.medium;

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onClick();
    }
  };

  const isOverdue = task.due_date && new Date(task.due_date) < new Date() && task.status !== 'done';

  return (
    <div
      draggable
      onDragStart={onDragStart}
      onClick={onClick}
      onKeyDown={handleKeyDown}
      role="button"
      tabIndex={0}
      className="bg-white rounded-lg shadow-sm border border-gray-200 p-3 cursor-pointer
                 hover:shadow-md hover:border-gray-300 transition-all duration-150
                 active:shadow-inner"
      aria-label={`Task: ${task.title}`}
    >
      {/* Priority badge */}
      <div className="flex items-center justify-between mb-2">
        <span
          className="text-xs font-medium px-2 py-0.5 rounded-full"
          style={{
            backgroundColor: priorityStyle.bg,
            color: priorityStyle.text,
            border: `1px solid ${priorityStyle.border}`,
          }}
        >
          {task.priority}
        </span>
        {task.tags && task.tags.length > 0 && (
          <div className="flex gap-1">
            {task.tags.slice(0, 2).map((tag, i) => (
              <span key={i} className="text-xs text-gray-500 bg-gray-100 px-1.5 py-0.5 rounded">
                {tag}
              </span>
            ))}
            {task.tags.length > 2 && (
              <span className="text-xs text-gray-400">+{task.tags.length - 2}</span>
            )}
          </div>
        )}
      </div>

      {/* Title */}
      <h3 className="text-sm font-medium text-gray-900 mb-1 leading-snug">
        {truncate(task.title, 80)}
      </h3>

      {/* Description preview */}
      {task.description && (
        <p className="text-xs text-gray-500 mb-2 leading-relaxed">
          {truncate(task.description, 120)}
        </p>
      )}

      {/* Footer: assignee + due date */}
      <div className="flex items-center justify-between mt-2 pt-2 border-t border-gray-100">
        <div className="flex items-center space-x-1.5">
          {task.assignee_name ? (
            <>
              <img
                src={task.assignee_avatar || `data:image/svg+xml;base64,${DEFAULT_AVATAR_SVG}`}
                alt={task.assignee_name}
                className="w-5 h-5 rounded-full"
              />
              <span className="text-xs text-gray-600">{task.assignee_name}</span>
            </>
          ) : (
            <span className="text-xs text-gray-400 italic">Unassigned</span>
          )}
        </div>

        {task.due_date && (
          <span className={`text-xs ${isOverdue ? 'text-red-600 font-medium' : 'text-gray-500'}`}>
            {isOverdue ? '⚠ ' : ''}
            {formatDate(task.due_date, { relative: true })}
          </span>
        )}
      </div>

      {/* Quick actions (visible on hover via CSS) */}
      <div className="hidden group-hover:flex absolute top-2 right-2 space-x-1">
        <button
          onClick={(e) => { e.stopPropagation(); onDelete(); }}
          className="p-1 text-gray-400 hover:text-red-500 rounded"
          aria-label="Delete task"
        >
          🗑
        </button>
      </div>
    </div>
  );
}

