/**
 * Settings Page
 * Handles user profile, billing, notifications, and account deletion.
 * TODO: break this into separate tab components when we refactor
 */
import React, { useState, useEffect } from 'react';
import api from '../utils/api';
import { password as checkPasswordStrength } from '../utils/helpers';

export default function Settings() {
  const [activeTab, setActiveTab] = useState('profile');
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);

  // Profile form
  const [profileForm, setProfileForm] = useState({ name: '', avatar_url: '' });

  // Password form
  const [passwordForm, setPasswordForm] = useState({
    current: '', newPassword: '', confirm: ''
  });
  const [passwordStrength, setPasswordStrength] = useState(null);

  // Billing
  const [subscription, setSubscription] = useState(null);

  // Notification prefs
  const [notifications, setNotifications] = useState({
    email_task_assigned: true,
    email_task_due: true,
    email_weekly_digest: false,
    push_mentions: true,
  });

  useEffect(() => {
    loadUserData();
  }, []);

  const loadUserData = async () => {
    try {
      setLoading(true);
      const [userRes, subRes] = await Promise.all([
        api.get('/auth/me'),
        api.get('/billing/subscription').catch(() => ({ data: null })),
      ]);
      setUser(userRes.data.user);
      setProfileForm({ name: userRes.data.user.name, avatar_url: userRes.data.user.avatar_url || '' });
      if (subRes.data) setSubscription(subRes.data);
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to load settings' });
    } finally {
      setLoading(false);
    }
  };

  const handleProfileSave = async (e) => {
    e.preventDefault();
    try {
      setSaving(true);
      const { data } = await api.put('/users/me', profileForm);
      setUser(prev => ({ ...prev, ...data.user }));
      setMessage({ type: 'success', text: 'Profile updated!' });
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to update profile' });
    } finally {
      setSaving(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    if (passwordForm.newPassword !== passwordForm.confirm) {
      setMessage({ type: 'error', text: 'Passwords do not match' });
      return;
    }
    const strength = checkPasswordStrength(passwordForm.newPassword);
    if (strength.score < 2) {
      setMessage({ type: 'error', text: 'Password is too weak. ' + strength.feedback.join(' ') });
      return;
    }
    try {
      setSaving(true);
      await api.post('/auth/change-password', {
        current_password: passwordForm.current,
        new_password: passwordForm.newPassword,
      });
      setPasswordForm({ current: '', newPassword: '', confirm: '' });
      setMessage({ type: 'success', text: 'Password changed successfully!' });
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.error || 'Failed to change password' });
    } finally {
      setSaving(false);
    }
  };

  const handleUpgrade = async () => {
    try {
      const { data } = await api.post('/billing/checkout');
      window.location.href = data.url;
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to start checkout' });
    }
  };

  const handleDeleteAccount = async () => {
    const confirmed = window.confirm(
      'Are you sure? This action cannot be undone. All your tasks and data will be permanently deleted.'
    );
    if (!confirmed) return;

    try {
      await api.delete('/users/me');
      localStorage.removeItem('access_token');
      window.location.href = '/';
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to delete account' });
    }
  };

  if (loading) {
    return <div className="flex justify-center p-12"><div className="animate-spin h-8 w-8 border-2 border-blue-600 rounded-full border-t-transparent" /></div>;
  }

  const tabs = [
    { id: 'profile', label: 'Profile' },
    { id: 'security', label: 'Security' },
    { id: 'billing', label: 'Billing' },
    { id: 'notifications', label: 'Notifications' },
  ];

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">Settings</h1>

      {message && (
        <div className={`mb-4 p-3 rounded-lg text-sm ${
          message.type === 'success' ? 'bg-green-50 text-green-700 border-green-200' : 'bg-red-50 text-red-700 border-red-200'
        } border`}>
          {message.text}
          <button onClick={() => setMessage(null)} className="ml-2 underline">×</button>
        </div>
      )}

      {/* Tab navigation */}
      <div className="flex border-b mb-6">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
              activeTab === tab.id
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Profile tab */}
      {activeTab === 'profile' && (
        <form onSubmit={handleProfileSave} className="space-y-4 max-w-lg">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
            <input type="text" value={profileForm.name}
              onChange={(e) => setProfileForm(p => ({ ...p, name: e.target.value }))}
              className="w-full border rounded-lg px-3 py-2" required />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Avatar URL</label>
            <input type="url" value={profileForm.avatar_url}
              onChange={(e) => setProfileForm(p => ({ ...p, avatar_url: e.target.value }))}
              className="w-full border rounded-lg px-3 py-2" placeholder="https://..." />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input type="email" value={user?.email || ''} disabled
              className="w-full border rounded-lg px-3 py-2 bg-gray-50 text-gray-500" />
            <p className="text-xs text-gray-400 mt-1">Contact support to change your email</p>
          </div>
          <button type="submit" disabled={saving}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
            {saving ? 'Saving...' : 'Save Profile'}
          </button>
        </form>
      )}

      {/* Danger zone */}
      {activeTab === 'profile' && (
        <div className="mt-12 pt-6 border-t border-red-200">
          <h3 className="text-lg font-medium text-red-600 mb-2">Danger Zone</h3>
          <p className="text-sm text-gray-600 mb-4">
            Once you delete your account, all of your data will be permanently removed.
          </p>
          <button onClick={handleDeleteAccount}
            className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
            Delete Account
          </button>
        </div>
      )}
    </div>
  );
}

