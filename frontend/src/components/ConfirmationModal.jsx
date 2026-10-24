import React from 'react';
import { AlertTriangle, X } from 'lucide-react';

const ConfirmationModal = ({
  isOpen,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  isDanger = false,
  onConfirm,
  onClose,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-md bg-cyber-card border border-cyber-border rounded-xl shadow-2xl p-6 overflow-hidden">
        {/* Glow accent bar */}
        <div className={`absolute top-0 left-0 right-0 h-1 ${isDanger ? 'bg-cyber-red shadow-red-glow' : 'bg-cyber-cyan shadow-cyan-glow'}`} />

        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-lg border ${isDanger ? 'bg-red-500/10 border-red-500/30 text-cyber-red' : 'bg-cyan-500/10 border-cyan-500/30 text-cyber-cyan'}`}>
              <AlertTriangle className="w-5 h-5" />
            </div>
            <h3 className="text-lg font-semibold text-cyber-text tracking-wide">{title}</h3>
          </div>
          <button
            onClick={onClose}
            className="text-cyber-muted hover:text-cyber-text transition-colors p-1"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-sm text-cyber-muted leading-relaxed mb-6 font-sans">
          {message}
        </p>

        <div className="flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-cyber-muted hover:text-cyber-text bg-cyber-secondary border border-cyber-border/40 rounded-lg transition-all hover:bg-cyber-panel"
          >
            {cancelText}
          </button>
          <button
            onClick={() => {
              onConfirm();
              onClose();
            }}
            className={`px-4 py-2 text-sm font-semibold rounded-lg transition-all shadow-md ${
              isDanger
                ? 'bg-cyber-red hover:bg-red-600 text-white shadow-red-glow'
                : 'bg-cyber-cyan hover:bg-cyan-400 text-black shadow-cyan-glow'
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmationModal;
