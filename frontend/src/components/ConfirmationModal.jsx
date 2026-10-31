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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/40 animate-fadeIn">
      <div className="relative w-full max-w-md bg-surface border border-bluegrey/40 rounded-2xl shadow-soft p-6 overflow-hidden">
        {/* Glow accent bar */}
        <div className={`absolute top-0 left-0 right-0 h-1 ${
          isDanger
            ? 'bg-gradient-to-r from-bad to-amber shadow-soft'
            : 'bg-gradient-to-r from-bluegrey to-forest shadow-soft'
        }`} />

        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border shadow-neumorph-sm ${
              isDanger
                ? 'bg-bad/15 border-bad/35 text-bad-ink'
                : 'bg-bluegrey/15 border-bluegrey/35 text-bluegrey-ink'
            }`}>
              <AlertTriangle className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-ink tracking-wide">{title}</h3>
          </div>
          <button
            onClick={onClose}
            className="text-muted hover:text-ink transition-colors p-1 rounded-lg hover:bg-sage"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-xs sm:text-sm text-muted leading-relaxed mb-6 font-sans">
          {message}
        </p>

        <div className="flex items-center justify-end gap-3 font-mono-code text-xs">
          <button
            onClick={onClose}
            className="px-4 py-2 font-medium text-muted hover:text-ink bg-sage border border-bluegrey/50 rounded-lg transition-all hover:bg-surface shadow-neumorph-sm"
          >
            {cancelText}
          </button>
          <button
            onClick={() => {
              onConfirm();
              onClose();
            }}
            className={`px-4 py-2 font-semibold rounded-lg transition-all shadow-md ${
              isDanger
                ? 'bg-bad hover:bg-bad/90 text-white shadow-soft'
                : 'bg-forest hover:bg-forest/90 text-white shadow-soft'
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
