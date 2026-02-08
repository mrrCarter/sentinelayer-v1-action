/**
 * TaskModal Component
 * Full task detail/edit modal with inline editing capabilities.
 */
import React, { useState, useEffect, useRef } from 'react';
import api from '../utils/api';
import { STATUS_CONFIG, PRIORITY_COLORS, formatDate } from '../utils/helpers';

export default function TaskModal({ task, onClose, onUpdate }) {
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({
    title: task.title,
    description: task.description || '',
    status: task.status,
    priority: task.priority,
    due_date: task.due_date ? task.due_date.split('T')[0] : '',
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const titleRef = useRef(null);
  const modalRef = useRef(null);

  useEffect(() => {
    if (editing && titleRef.current) {
      titleRef.current.focus();
    }
  }, [editing]);

  // Close on Escape key
  useEffect(() => {
    const handleEsc = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  // Close on backdrop click
  const handleBackdropClick = (e) => {
    if (e.target === modalRef.current) onClose();
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      const { data } = await api.put(`/tasks/${task.id}`, form);
      onUpdate(data.task);
      setEditing(false);
    } catch (err) {
      setError('Failed to save changes. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleChange = (field, value) => {
    setForm(prev => ({ ...prev, [field]: value }));
  };

  return (
    <div
      ref={modalRef}
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      onClick={handleBackdropClick}
    >
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b">
          {editing ? (
            <input
              ref={titleRef}
              type="text"
              value={form.title}
              onChange={(e) => handleChange('title', e.target.value)}
              className="text-xl font-bold text-gray-900 w-full border-b-2 border-blue-500 pb-1 outline-none"
            />
          ) : (
            <h2 className="text-xl font-bold text-gray-900">{task.title}</h2>
          )}
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-2xl ml-4">
            ×
          </button>
        </div>

        {error && (
          <div className="mx-6 mt-4 p-3 bg-red-50 border border-red-200 rounded text-red-700 text-sm">
            {error}
          </div>
        )}

        {/* Body */}
        <div className="p-6 space-y-4">
          {/* Status & Priority row */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-1">Status</label>
              {editing ? (
                <select
                  value={form.status}
                  onChange={(e) => handleChange('status', e.target.value)}
                  className="w-full border rounded-lg px-3 py-2"
                >
                  {Object.entries(STATUS_CONFIG).map(([key, cfg]) => (
                    <option key={key} value={key}>{cfg.label}</option>
                  ))}
                </select>
              ) : (
                <span className="inline-flex items-center space-x-1 text-sm">
                  <span style={{ color: STATUS_CONFIG[task.status]?.color }}>
                    {STATUS_CONFIG[task.status]?.icon}
                  </span>
                  <span>{STATUS_CONFIG[task.status]?.label}</span>
                </span>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-600 mb-1">Priority</label>
              {editing ? (
                <select
                  value={form.priority}
                  onChange={(e) => handleChange('priority', e.target.value)}
                  className="w-full border rounded-lg px-3 py-2"
                >
                  {Object.keys(PRIORITY_COLORS).map(p => (
                    <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
                  ))}
                </select>
              ) : (
                <span className="text-sm capitalize">{task.priority}</span>
              )}
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-gray-600 mb-1">Description</label>
            {editing ? (
              <textarea
                value={form.description}
                onChange={(e) => handleChange('description', e.target.value)}
                rows={4}
                className="w-full border rounded-lg px-3 py-2 resize-none"
                placeholder="Add a description..."
              />
            ) : (
              <p className="text-sm text-gray-700 whitespace-pre-wrap">
                {task.description || 'No description'}
              </p>
            )}
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Created:</span>{' '}
              <span>{formatDate(task.created_at)}</span>
            </div>
            <div>
              <span className="text-gray-500">Updated:</span>{' '}
              <span>{formatDate(task.updated_at)}</span>
            </div>
            <div>
              <span className="text-gray-500">Assignee:</span>{' '}
              <span>{task.assignee_name || 'Unassigned'}</span>
            </div>
            <div>
              <span className="text-gray-500">Creator:</span>{' '}
              <span>{task.creator_name || '—'}</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-6 border-t bg-gray-50 rounded-b-xl">
          {editing ? (
            <>
              <button
                onClick={() => { setEditing(false); setForm({ ...form, ...task }); }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
            </>
          ) : (
            <button
              onClick={() => setEditing(true)}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Edit Task
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

